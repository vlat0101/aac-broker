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

    fn persist(&self, map: &HashMap<(String, String), StoredGrant>) {
        let list: Vec<&StoredGrant> = map.values().collect();
        if let Ok(json) = serde_json::to_vec_pretty(&list) {
            let tmp = self.path.with_extension("tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }

    /// Is there an unexpired grant for this device and item?
    pub fn is_granted(&self, fingerprint: &str, item_id: &str) -> bool {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let key = (fingerprint.to_string(), item_id.to_string());
        match map.get(&key) {
            Some(g) if g.permanent || g.expires_at > now() => true,
            Some(_) => {
                map.remove(&key);
                self.persist(&map);
                false
            }
            None => false,
        }
    }

    pub fn add(
        &self,
        fingerprint: &str,
        agent: &str,
        item_id: &str,
        item_name: &str,
        domain: Option<&str>,
        ttl_secs: u64,
    ) {
        self.insert(StoredGrant {
            fingerprint: fingerprint.to_string(),
            agent: agent.to_string(),
            item_id: item_id.to_string(),
            item_name: item_name.to_string(),
            domain: domain.map(str::to_string),
            permanent: false,
            expires_at: now() + ttl_secs,
        });
    }

    /// Approve this site for this device until it is revoked.
    pub fn add_permanent(
        &self,
        fingerprint: &str,
        agent: &str,
        item_id: &str,
        item_name: &str,
        domain: Option<&str>,
    ) {
        self.insert(StoredGrant {
            fingerprint: fingerprint.to_string(),
            agent: agent.to_string(),
            item_id: item_id.to_string(),
            item_name: item_name.to_string(),
            domain: domain.map(str::to_string),
            permanent: true,
            expires_at: 0,
        });
    }

    fn insert(&self, grant: StoredGrant) {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        map.insert(
            (grant.fingerprint.clone(), grant.item_id.clone()),
            grant,
        );
        self.persist(&map);
    }

    /// Drop every approval belonging to a device (used when it is unpaired).
    /// A revoked device's approvals are not just useless, they are a record of
    /// what it was allowed to read.
    pub fn forget_device(&self, fingerprint: &str) -> usize {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let before = map.len();
        map.retain(|(fp, _), _| fp != fingerprint);
        let removed = before - map.len();
        if removed > 0 {
            self.persist(&map);
        }
        removed
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

    pub fn revoke(&self, fingerprint: &str, item_id: &str) -> bool {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        let removed = map
            .remove(&(fingerprint.to_string(), item_id.to_string()))
            .is_some();
        if removed {
            self.persist(&map);
        }
        removed
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
            self.persist(&map);
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
    fn grant_is_scoped_to_the_device_fingerprint_and_item() {
        let d = tmp("scope");
        let g = Grants::load(&d);
        g.add("fp-aaa", "hermes-lxc", "item-1", "GitHub", Some("github.com"), 300);
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
        g.add("fp-aaa", "hermes-lxc", "item-1", "GitHub", Some("github.com"), 0); // already expired
        assert!(!g.is_granted("fp-aaa", "item-1"));
        assert!(g.active().is_empty());
    }

    #[test]
    fn a_permanent_grant_never_expires_and_never_prunes() {
        let d = tmp("permanent");
        {
            let g = Grants::load(&d);
            g.add_permanent("fp-aaa", "hermes-lxc", "item-1", "GitHub", Some("github.com"));
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
        assert!(g.revoke("fp-aaa", "item-1"));
        assert!(!g.is_granted("fp-aaa", "item-1"));
    }

    #[test]
    fn approvals_are_listed_per_device_and_dropped_with_it() {
        let d = tmp("per-agent");
        let g = Grants::load(&d);
        g.add_permanent("fp-aaa", "hermes-lxc", "item-1", "GitHub", Some("github.com"));
        g.add("fp-aaa", "hermes-lxc", "item-2", "Grafana", Some("grafana.example.com"), 600);
        g.add_permanent("fp-bbb", "grokbot", "item-3", "Stripe", Some("api.stripe.com"));

        let mine = g.for_agent("fp-aaa");
        assert_eq!(mine.len(), 2);
        assert!(mine[0].permanent, "permanent approvals sort first");
        assert!(g.for_agent("fp-bbb").len() == 1);

        assert_eq!(g.forget_device("fp-aaa"), 2);
        assert!(g.for_agent("fp-aaa").is_empty());
        assert_eq!(g.for_agent("fp-bbb").len(), 1, "other devices keep theirs");
    }

    #[test]
    fn grants_survive_reload_and_revoke_sticks() {
        let d = tmp("reload");
        {
            let g = Grants::load(&d);
            g.add("fp-aaa", "hermes-lxc", "item-1", "GitHub", Some("github.com"), 600);
        }
        let g = Grants::load(&d);
        assert!(g.is_granted("fp-aaa", "item-1"));
        assert!(g.revoke("fp-aaa", "item-1"));
        assert!(!g.is_granted("fp-aaa", "item-1"));
        let again = Grants::load(&d);
        assert!(!again.is_granted("fp-aaa", "item-1"));
    }

    #[test]
    fn expired_grants_are_removed_from_disk_not_just_memory() {
        let d = tmp("persist-prune");
        {
            let g = Grants::load(&d);
            g.add("fp-aaa", "hermes-lxc", "item-1", "GitHub", Some("github.com"), 0);
            assert!(g.active().is_empty());
        }
        let text = std::fs::read_to_string(d.join("grants.json")).expect("read");
        assert!(!text.contains("item-1"), "expired grant survived on disk");
    }
}
