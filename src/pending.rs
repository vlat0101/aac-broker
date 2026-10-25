//! Requests waiting for a human decision.
//!
//! One entry per request; the protocol callback blocks on the receiver while the
//! page (or a timeout) resolves it. Nothing here decides anything — the decision
//! arrives from the approval surface.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

use crate::vault::Candidate;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    Deny,
    /// Approve exactly one item out of the candidates shown.
    Approve { item_id: String },
    /// Approve and remember for the given number of seconds.
    ApproveRemember { item_id: String, secs: u64 },
    /// Approve and remember until revoked (a permanent site approval).
    ApprovePermanent { item_id: String },
}

#[derive(Debug, Clone)]
pub struct PendingRequest {
    /// Opened while the vault was locked: `items` is empty until it is unlocked.
    /// The request is held anyway — the alternative is throwing away a request
    /// the operator could still answer within the window.
    pub locked: bool,
    /// The agent asked by item id rather than by host, which changes how the
    /// candidates are resolved once the vault opens.
    pub by_id: bool,
    pub id: String,
    /// Verified device label from the pairing record.
    pub device: String,
    /// Verified device fingerprint (hex). Grants and audit key on this, never on
    /// the display name: two devices may share a name.
    pub fingerprint: String,
    /// Agent name the requester *claims* (unverified).
    pub agent_claim: Option<String>,
    /// Reason the requester *claims* (unverified).
    pub reason: Option<String>,
    /// The string the agent actually asked for, before parsing.
    pub requested: String,
    /// Every vault item whose host matched. Exactly one is released; when there
    /// are several, the operator picks. Never released wholesale.
    pub items: Vec<Candidate>,
    pub created: Instant,
}

/// What the waiting task receives. It carries the candidates because a request
/// that arrived while the vault was locked gets them only when the operator
/// unlocks — the service's own snapshot would still be empty at decision time.
#[derive(Debug)]
pub struct Decision {
    pub choice: Choice,
    pub items: Vec<Candidate>,
}

struct Entry {
    req: PendingRequest,
    tx: Option<oneshot::Sender<Decision>>,
}

#[derive(Default)]
pub struct Pending {
    items: Mutex<HashMap<String, Entry>>,
}

impl Pending {
    /// Register a request and hand back the receiver the caller awaits.
    pub fn open(&self, req: PendingRequest) -> oneshot::Receiver<Decision> {
        let (tx, rx) = oneshot::channel();
        let mut items = self.items.lock().unwrap_or_else(|p| p.into_inner());
        items.insert(
            req.id.clone(),
            Entry {
                req,
                tx: Some(tx),
            },
        );
        rx
    }

    pub fn list(&self) -> Vec<PendingRequest> {
        let items = self.items.lock().unwrap_or_else(|p| p.into_inner());
        let mut out: Vec<PendingRequest> = items.values().map(|e| e.req.clone()).collect();
        out.sort_by_key(|r| r.created);
        out
    }

    pub fn get(&self, id: &str) -> Option<PendingRequest> {
        let items = self.items.lock().unwrap_or_else(|p| p.into_inner());
        items.get(id).map(|e| e.req.clone())
    }

    /// Resolve a request and hand back the record that was decided.
    ///
    /// Returns `None` when there is nothing to decide: already gone (timed out
    /// or decided twice) or the waiter has dropped its receiver (the timeout
    /// arm fired). The caller needs the snapshot because the entry is removed
    /// here — reading it back from `get` afterwards always missed, which is how
    /// the "remember this approval" option came to never store anything.
    pub fn resolve(&self, id: &str, choice: Choice) -> Option<PendingRequest> {
        let mut items = self.items.lock().unwrap_or_else(|p| p.into_inner());
        let mut entry = items.remove(id)?;
        let tx = entry.tx.take()?;
        let req = entry.req;
        let decision = Decision {
            choice,
            items: req.items.clone(),
        };
        match tx.send(decision) {
            Ok(()) => Some(req),
            Err(_) => None,
        }
    }

    /// Drop a request that timed out, so the page stops showing it.
    pub fn expire(&self, id: &str) {
        let mut items = self.items.lock().unwrap_or_else(|p| p.into_inner());
        items.remove(id);
    }

    /// Drop every waiting request from one device (used when it is revoked).
    /// Dropping the sender makes the waiting task take its deny path.
    pub fn expire_for(&self, fingerprint: &str) -> usize {
        let mut items = self.items.lock().unwrap_or_else(|p| p.into_inner());
        let ids: Vec<String> = items
            .iter()
            .filter(|(_, e)| e.req.fingerprint == fingerprint)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &ids {
            items.remove(id);
        }
        ids.len()
    }

    /// Fill in the candidates for a request that was opened while locked.
    /// Returns false if the request is gone (decided or timed out meanwhile).
    pub fn fill(&self, id: &str, items: Vec<crate::vault::Candidate>) -> bool {
        let mut map = self.items.lock().unwrap_or_else(|p| p.into_inner());
        match map.get_mut(id) {
            Some(entry) => {
                entry.req.items = items;
                entry.req.locked = false;
                true
            }
            None => false,
        }
    }

    /// Requests still waiting for the vault to open.
    pub fn awaiting_vault(&self) -> Vec<PendingRequest> {
        self.items
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter(|e| e.req.locked)
            .map(|e| e.req.clone())
            .collect()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.items
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }
}

/// How long a request may sit waiting before it is denied.
/// Long enough to walk to a phone, read the card, and pick between two items.
pub const DEFAULT_APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);

#[cfg(test)]
mod tests {
    use super::*;

    fn req(id: &str) -> PendingRequest {
        PendingRequest {
            locked: false,
            by_id: false,
            id: id.to_string(),
            device: "hermes-lxc".to_string(),
            fingerprint: "fingerprint".to_string(),
            agent_claim: Some("hermes".to_string()),
            reason: Some("check gh auth".to_string()),
            requested: "github.com".to_string(),
            items: vec![Candidate {
                id: "item-1".to_string(),
                name: "GitHub".to_string(),
                username: Some("agent@example.com".to_string()),
                uris: vec![],
            }],
            created: Instant::now(),
        }
    }

    #[tokio::test]
    async fn resolve_delivers_the_choice_exactly_once_and_returns_the_record() {
        let p = Pending::default();
        let rx = p.open(req("a"));
        assert_eq!(p.len(), 1);
        let decided = p.resolve("a", Choice::Approve { item_id: "item-1".into() }).expect("decided");
        assert_eq!(decided.id, "a");
        assert_eq!(decided.fingerprint, "fingerprint");
        assert_eq!(
            rx.await.expect("decision").choice,
            Choice::Approve {
                item_id: "item-1".into()
            }
        );
        assert_eq!(p.len(), 0);
        // Second resolve must not pretend to work.
        assert!(p.resolve("a", Choice::Deny).is_none());
    }

    #[tokio::test]
    async fn expired_request_cannot_be_approved_afterwards() {
        let p = Pending::default();
        let rx = p.open(req("b"));
        p.expire("b");
        assert!(p.resolve("b", Choice::Approve { item_id: "item-1".into() }).is_none());
        assert!(rx.await.is_err(), "receiver must be dropped, not resolved");
    }

    #[tokio::test]
    async fn the_decision_carries_the_candidates_filled_after_it_was_opened() {
        let p = Pending::default();
        let mut r = req("held");
        r.locked = true;
        r.items.clear();
        let rx = p.open(r);
        assert_eq!(p.awaiting_vault().len(), 1);

        assert!(p.fill(
            "held",
            vec![Candidate {
                id: "item-late".to_string(),
                name: "GitHub".to_string(),
                username: None,
                uris: vec!["https://github.com".to_string()],
            }]
        ));
        assert!(p.awaiting_vault().is_empty(), "filled request is no longer held");

        p.resolve("held", Choice::Approve { item_id: "item-late".into() });
        let decision = rx.await.expect("decision");
        assert_eq!(
            decision.items.len(),
            1,
            "the waiting side must see what the operator saw"
        );
        assert_eq!(decision.items[0].id, "item-late");
    }

    #[tokio::test]
    async fn revoking_a_device_drops_only_its_requests() {
        let p = Pending::default();
        let _a = p.open(req("a"));
        let mut other = req("b");
        other.fingerprint = "someone-else".to_string();
        let _b = p.open(other);
        assert_eq!(p.expire_for("fingerprint"), 1);
        assert_eq!(p.len(), 1);
        assert!(p.resolve("a", Choice::Deny).is_none());
    }

    #[tokio::test]
    async fn a_dropped_waiter_is_not_reported_as_decided() {
        // The timeout arm dropped the receiver: the page must not answer "done".
        let p = Pending::default();
        let rx = p.open(req("c"));
        drop(rx);
        assert!(p.resolve("c", Choice::Approve { item_id: "item-1".into() }).is_none());
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn list_is_ordered_and_carries_the_unverified_claims() {
        let p = Pending::default();
        let _pending_rx = p.open(req("x"));  // hold it: dropping the receiver resolves as abandoned
        let list = p.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].agent_claim.as_deref(), Some("hermes"));
        assert_eq!(list[0].device, "hermes-lxc");
    }
}
