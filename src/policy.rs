//! Remembered approvals.
//!
//! A grant is keyed by `(agent, item_id)` — never by domain, and never "all
//! domains". Expiry is absolute (epoch seconds), so a restart cannot extend a
//! grant, and pruning is just comparing the clock.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `racv.com.au` and `www.racv.com.au` are the same site; `racv.com.au` and `foo.com.au` are not.
fn same_site_domain(a: &str, b: &str) -> bool {
    fn norm(h: &str) -> String {
        let h = h.trim().to_lowercase();
        let h = h.trim_end_matches('.');
        h.strip_prefix("www.").unwrap_or(h).to_string()
    }
    !a.trim().is_empty() && !b.trim().is_empty() && norm(a) == norm(b)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredGrant {
    /// Verified device fingerprint. Grants key on this, never on the display
    /// name: a second device can be paired under an existing name and would
    /// otherwise inherit its grants.
    pub fingerprint: String,
    /// Display name at the time of the grant, shown on the page only.
    pub agent: String,
    pub item_id: String,
    /// Human label kept for the "what is still open" view.
    pub item_name: String,
    /// The site that was requested when the grant was made (`github.com`), so a
    /// grant reads as "this site" rather than as an opaque vault item id.
    #[serde(default)]
    pub domain: Option<String>,
    /// A permanent grant ignores the clock: it stays until revoked by hand.
    /// This is a separate flag, not `expires_at == 0`, because 0 already means
    /// "expired at the epoch" for timed grants.
    #[serde(default)]
    pub permanent: bool,
    pub expires_at: u64,
}

pub struct Grants {
    path: PathBuf,
    map: Mutex<HashMap<(String, String), StoredGrant>>,
}

impl Grants {
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("grants.json");
        let map = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str::<Vec<StoredGrant>>(&t).ok())
            .map(|v| {
                v.into_iter()
                    .map(|g| ((g.fingerprint.clone(), g.item_id.clone()), g))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            path,
            map: Mutex::new(map),
        }
    }

    fn persist(&self, map: &HashMap<(String, String), StoredGrant>) -> Result<(), String> {
        let list: Vec<&StoredGrant> = map.values().collect();
        let json = serde_json::to_vec_pretty(&list).map_err(|e| format!("grants: {e}"))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, json).map_err(|e| format!("grants write: {e}"))?;
        // A failed rename leaves the old file on disk, so the grant would load again on the next
        // start. Report it instead of telling the operator a permanent grant is revoked.
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("grants rename: {e}"))?;
        Ok(())
    }

    /// Is there an unexpired grant for this device and item, ignoring the site?
    /// Kept because the page shows a device's grants without a host; anything that can release a
    /// credential must use `is_granted_for` instead.
    #[allow(dead_code)]
    pub fn is_granted(&self, fingerprint: &str, item_id: &str) -> bool {
        self.check_grant(fingerprint, item_id, None)
    }

    /// Is there an unexpired grant for this device, item **and site**?
    ///
    /// The site half is not decoration: a grant means "this agent may read this item for this
    /// host", so a request for a different host must fall through to the operator even when the
    /// item id matches. A grant recorded without a domain (an older file) falls through too — the
    /// safe direction, at the cost of one extra tap.
    pub fn is_granted_for(&self, fingerprint: &str, item_id: &str, host: &str) -> bool {
        self.check_grant(fingerprint, item_id, Some(host))
    }

    fn check_grant(&self, fingerprint: &str, item_id: &str, host: Option<&str>) -> bool {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let key = (fingerprint.to_string(), item_id.to_string());
        match map.get(&key) {
            Some(g) if g.permanent || g.expires_at > now() => match host {
                None => true,
                Some(h) => g.domain.as_deref().is_some_and(|d| same_site_domain(d, h)),
            },
            Some(_) => {
                map.remove(&key);
                let _ = self.persist(&map);
                false
            }
            None => false,
        }
    }

    /// Approve this site for this device for `ttl_secs`, then forget it.
    pub fn add(
        &self,
        fingerprint: &str,
        agent: &str,
        item_id: &str,
        item_name: &str,
        domain: Option<&str>,
        ttl_secs: u64,
    ) -> Result<(), String> {
        self.insert(StoredGrant {
            fingerprint: fingerprint.to_string(),
            agent: agent.to_string(),
            item_id: item_id.to_string(),
            item_name: item_name.to_string(),
            domain: domain.map(str::to_string),
            permanent: false,
            expires_at: now() + ttl_secs,
        })
    }

    /// Approve this site for this device until it is revoked.
    pub fn add_permanent(
        &self,
        fingerprint: &str,
        agent: &str,
        item_id: &str,
        item_name: &str,
        domain: Option<&str>,
    ) -> Result<(), String> {
        self.insert(StoredGrant {
            fingerprint: fingerprint.to_string(),
            agent: agent.to_string(),
            item_id: item_id.to_string(),
            item_name: item_name.to_string(),
            domain: domain.map(str::to_string),
            permanent: true,
            expires_at: 0,
        })
    }

    fn insert(&self, grant: StoredGrant) -> Result<(), String> {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        map.insert(
            (grant.fingerprint.clone(), grant.item_id.clone()),
            grant,
        );
        self.persist(&map)
    }

    /// Drop every approval belonging to a device (used when it is unpaired).
    /// A revoked device's approvals are not just useless, they are a record of
    /// what it was allowed to read.
    pub fn forget_device(&self, fingerprint: &str) -> Result<usize, String> {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let before = map.len();
        map.retain(|(fp, _), _| fp != fingerprint);
        let removed = before - map.len();
        if removed > 0 {
            self.persist(&map)?;
        }
        Ok(removed)
    }

    /// Live approvals for one device: what the operator sees when they click an
    /// agent open. Permanent first, then soonest expiry.
    pub fn for_agent(&self, fingerprint: &str) -> Vec<StoredGrant> {
        let mut out: Vec<StoredGrant> = self
            .active()
            .into_iter()
            .filter(|g| g.fingerprint == fingerprint)
            .collect();
        out.sort_by_key(|g| (!g.permanent, g.expires_at));
        out
    }

    pub fn revoke(&self, fingerprint: &str, item_id: &str) -> Result<bool, String> {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let removed = map
            .remove(&(fingerprint.to_string(), item_id.to_string()))
            .is_some();
        if removed {
            self.persist(&map)?;
        }
        Ok(removed)
    }

    /// Live grants, newest expiry last — shown on the page so nothing is silently open.
    pub fn active(&self) -> Vec<StoredGrant> {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let t = now();
        // Permanent grants are never pruned; only timed ones fall off the clock.
        let expired: Vec<(String, String)> = map
            .iter()
            .filter(|(_, g)| !g.permanent && g.expires_at <= t)
            .map(|(k, _)| k.clone())
            .collect();
        let had_expired = !expired.is_empty();
        for k in expired {
            map.remove(&k);
        }
        if had_expired {
            // Pruning is best-effort: the row is already gone from memory, and the next successful
            // write clears it from disk. Returning stale rows would be worse than a retry.
            let _ = self.persist(&map);
        }
        let mut out: Vec<StoredGrant> = map.values().cloned().collect();
        out.sort_by_key(|g| (!g.permanent, g.expires_at));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aac-broker-grants-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    #[test]
    fn a_grant_only_covers_the_site_it_was_made_for() {
        let d = tmp("site");
        let g = Grants::load(&d);
        g.add_permanent("fp-aaa", "agent", "item-1", "RACV", Some("racv.com.au"))
            .expect("grant");

        assert!(g.is_granted_for("fp-aaa", "item-1", "racv.com.au"));
        assert!(g.is_granted_for("fp-aaa", "item-1", "www.racv.com.au"));
        // Same item id, different site: the hole that let a remembered grant release a credential
        // the operator never approved for that host.
        assert!(!g.is_granted_for("fp-aaa", "item-1", "other.com.au"));
        // A grant recorded without a domain falls through to the operator.
        g.add_permanent("fp-aaa", "agent", "item-2", "Legacy", None)
            .expect("grant");
        assert!(!g.is_granted_for("fp-aaa", "item-2", "racv.com.au"));
    }

    #[test]
    fn grant_is_scoped_to_the_device_fingerprint_and_item() {
        let d = tmp("scope");
        let g = Grants::load(&d);
        g.add("fp-aaa", "hermes-lxc", "item-1", "GitHub", Some("github.com"), 300).expect("grant");
        assert!(g.is_granted("fp-aaa", "item-1"));
        // A different device, even with the same display name, gets nothing.
        assert!(!g.is_granted("fp-bbb", "item-1"));
        assert!(!g.is_granted("fp-aaa", "item-2"));
        assert!(!g.is_granted("hermes-lxc", "item-1"));
    }

    #[test]
    fn expired_grant_is_not_honoured_and_disappears() {
        let d = tmp("expiry");
        let g = Grants::load(&d);
        g.add("fp-aaa", "hermes-lxc", "item-1", "GitHub", Some("github.com"), 0)
            .expect("grant"); // already expired
        assert!(!g.is_granted("fp-aaa", "item-1"));
        assert!(g.active().is_empty());
    }

    #[test]
    fn a_permanent_grant_never_expires_and_never_prunes() {
        let d = tmp("permanent");
        {
            let g = Grants::load(&d);
            g.add_permanent("fp-aaa", "hermes-lxc", "item-1", "GitHub", Some("github.com"))
            .expect("grant");
            // even with the clock pushed far past any timed grant
            assert!(g.is_granted("fp-aaa", "item-1"));
        }
        let g = Grants::load(&d);
        assert!(g.is_granted("fp-aaa", "item-1"));
        let live = g.active();
        assert_eq!(live.len(), 1);
        assert!(live[0].permanent);
        assert_eq!(live[0].domain.as_deref(), Some("github.com"));
        // and only an explicit revoke ends it
        assert!(g.revoke("fp-aaa", "item-1").expect("revoke"));
        assert!(!g.is_granted("fp-aaa", "item-1"));
    }

    #[test]
    fn approvals_are_listed_per_device_and_dropped_with_it() {
        let d = tmp("per-agent");
        let g = Grants::load(&d);
        g.add_permanent("fp-aaa", "hermes-lxc", "item-1", "GitHub", Some("github.com"))
            .expect("grant");
        g.add("fp-aaa", "hermes-lxc", "item-2", "Grafana", Some("grafana.example.com"), 600).expect("grant");
        g.add_permanent("fp-bbb", "grokbot", "item-3", "Stripe", Some("api.stripe.com"))
            .expect("grant");

        let mine = g.for_agent("fp-aaa");
        assert_eq!(mine.len(), 2);
        assert!(mine[0].permanent, "permanent approvals sort first");
        assert!(g.for_agent("fp-bbb").len() == 1);

        assert_eq!(g.forget_device("fp-aaa").expect("forget"), 2);
        assert!(g.for_agent("fp-aaa").is_empty());
        assert_eq!(g.for_agent("fp-bbb").len(), 1, "other devices keep theirs");
    }

    #[test]
    fn grants_survive_reload_and_revoke_sticks() {
        let d = tmp("reload");
        {
            let g = Grants::load(&d);
            g.add("fp-aaa", "hermes-lxc", "item-1", "GitHub", Some("github.com"), 600).expect("grant");
        }
        let g = Grants::load(&d);
        assert!(g.is_granted("fp-aaa", "item-1"));
        assert!(g.revoke("fp-aaa", "item-1").expect("revoke"));
        assert!(!g.is_granted("fp-aaa", "item-1"));
        let again = Grants::load(&d);
        assert!(!again.is_granted("fp-aaa", "item-1"));
    }

    #[test]
    fn expired_grants_are_removed_from_disk_not_just_memory() {
        let d = tmp("persist-prune");
        {
            let g = Grants::load(&d);
            g.add("fp-aaa", "hermes-lxc", "item-1", "GitHub", Some("github.com"), 0).expect("grant");
            assert!(g.active().is_empty());
        }
        let text = std::fs::read_to_string(d.join("grants.json")).expect("read");
        assert!(!text.contains("item-1"), "expired grant survived on disk");
    }
}
