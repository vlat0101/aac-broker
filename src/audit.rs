//! Append-only audit trail.
//!
//! One JSON object per line, in the state directory, mode 0600. Chosen over
//! SQLite deliberately: the only query that matters is "what happened", and a
//! line-oriented file can be read with `tail`/`jq` on a box with no tooling.
//! Retention is enforced by truncating entries older than the retention window
//! on startup and daily thereafter.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

pub const RETENTION_DAYS: u64 = 90;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Debug, Serialize)]
pub struct Entry<'a> {
    pub ts: u64,
    /// request | decision | unlock | lock | pairing | relay | grant | alert
    pub kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<&'a str>,
    /// Verified device fingerprint. A display name is not identity: this is the
    /// only field that can answer "which device received it".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'a str>,
    /// allowed | denied | timeout | remembered | error
    pub outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<&'a str>,
}

pub struct Audit {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Audit {
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("audit.jsonl");
        let audit = Self {
            path,
            lock: Mutex::new(()),
        };
        audit.prune(RETENTION_DAYS);
        audit
    }

    /// Append one entry. Returns Err when the record could not be written, so a
    /// caller can fail closed: an unauditable release must not happen.
    pub fn write(&self, entry: Entry<'_>) -> Result<(), String> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let line = serde_json::to_string(&entry)
            .map_err(|e| format!("serialise audit entry: {e}"))?;

        // Refuse to write through a symlink: the state dir is 0700 root-owned,
        // but a pre-planted link would redirect the trail somewhere else.
        if let Ok(meta) = std::fs::symlink_metadata(&self.path) {
            if meta.file_type().is_symlink() {
                return Err("audit.jsonl is a symlink; refusing to write".to_string());
            }
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
            .map_err(|e| format!("open audit log: {e}"))?;
        // Tighten an existing file that was created under a looser umask.
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        writeln!(f, "{line}").map_err(|e| format!("append audit log: {e}"))?;
        Ok(())
    }

    /// Keep the last N days. Runs at startup and on a timer; takes the write
    /// lock so a prune cannot interleave with an append.
    pub fn prune(&self, days: u64) {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        // Same symlink rule as `write`: pruning through a link would replace
        // the link with a regular file and hide the redirect.
        if std::fs::symlink_metadata(&self.path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return;
        }
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return;
        };
        let cutoff = now().saturating_sub(days * 86_400);
        let kept: Vec<&str> = text
            .lines()
            .filter(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .ok()
                    .and_then(|v| v.get("ts").and_then(|t| t.as_u64()))
                    .is_some_and(|ts| ts >= cutoff)
            })
            .collect();
        if kept.len() == text.lines().count() {
            return;
        }
        let mut joined = kept.join("\n");
        if !joined.is_empty() {
            joined.push('\n');
        }
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, joined).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }

    /// Last `n` entries, newest first, for the page.
    /// One page of entries, newest first. `page` is 1-based; returns the rows
    /// and the total count so the page can show "page 2 of 7".
    pub fn page(&self, page: usize, per_page: usize) -> (Vec<serde_json::Value>, usize) {
        let all = self.rows();
        let total = all.len();
        let per_page = per_page.max(1);
        let skip = page.saturating_sub(1).saturating_mul(per_page);
        // Slice from the end: newest first, without reading the file backwards.
        let end = total.saturating_sub(skip);
        let start = end.saturating_sub(per_page);
        let mut rows: Vec<serde_json::Value> = all[start..end].to_vec();
        rows.reverse();
        (rows, total)
    }

    fn rows(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.path)
            .map(|text| {
                text.lines()
                    .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub fn tail(&self, n: usize) -> Vec<serde_json::Value> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        let out: Vec<serde_json::Value> = text
            .lines()
            .rev()
            .take(n)
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aac-broker-audit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    #[test]
    fn writes_and_reads_back_newest_first() {
        let d = tmp("write");
        let a = Audit::load(&d);
        for i in 0..3 {
            let _ = a.write(Entry {
                ts: now() + i,
                kind: "decision",
                device: Some("hermes-lxc"),
                fingerprint: Some("abc123"),
                agent: None,
                requested: Some("github.com"),
                item_id: None,
                item_name: Some("GitHub"),
                reason: None,
                outcome: "allowed",
                detail: None,
            });
        }
        let tail = a.tail(2);
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[1]["outcome"], "allowed");
        assert_eq!(tail[1]["device"], "hermes-lxc");
    }

    #[test]
    fn prune_drops_entries_past_retention() {
        let d = tmp("prune");
        let a = Audit::load(&d);
        let old = now().saturating_sub((RETENTION_DAYS + 1) * 86_400);
        std::fs::write(
            d.join("audit.jsonl"),
            format!(
                "{{\"ts\":{old},\"kind\":\"decision\",\"outcome\":\"denied\"}}\n{{\"ts\":{},\"kind\":\"decision\",\"outcome\":\"allowed\"}}\n",
                now()
            ),
        )
        .expect("seed");
        a.prune(RETENTION_DAYS);
        let text = std::fs::read_to_string(d.join("audit.jsonl")).expect("read");
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("allowed"));
    }

    #[test]
    fn write_fails_closed_through_a_symlinked_log() {
        let d = tmp("symlink");
        let target = d.join("elsewhere.log");
        std::fs::write(&target, b"x").expect("seed");
        std::os::unix::fs::symlink(&target, d.join("audit.jsonl")).expect("symlink");
        let a = Audit::load(&d);
        let err = a
            .write(Entry {
                ts: now(),
                kind: "decision",
                device: Some("d"),
                fingerprint: None,
                agent: None,
                requested: None,
                item_id: None,
                item_name: None,
                reason: None,
                outcome: "allowed",
                detail: None,
            })
            .expect_err("must refuse");
        assert!(err.contains("symlink"));
        // The redirect target must be untouched.
        assert_eq!(std::fs::read_to_string(&target).expect("read"), "x");
    }

    #[test]
    fn audit_file_is_created_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("mode");
        let a = Audit::load(&d);
        a.write(Entry {
            ts: now(),
            kind: "decision",
            device: None,
            fingerprint: None,
            agent: None,
            requested: None,
            item_id: None,
            item_name: None,
            reason: None,
            outcome: "allowed",
            detail: None,
        })
        .expect("write");
        let mode = std::fs::metadata(d.join("audit.jsonl"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn no_secret_material_is_ever_written() {
        let d = tmp("nosc");
        let a = Audit::load(&d);
        a.write(Entry {
            ts: now(),
            kind: "decision",
            device: Some("hermes-lxc"),
            fingerprint: Some("abc123"),
            agent: Some("hermes"),
            requested: Some("github.com"),
            item_id: Some("item-1"),
            item_name: Some("GitHub"),
            reason: Some("check gh auth"),
            outcome: "allowed",
            detail: None,
        })
        .expect("write");
        let text = std::fs::read_to_string(d.join("audit.jsonl")).expect("read");
        // The type has no field for a password, username, totp or notes: prove
        // the recorded shape cannot carry one.
        for forbidden in ["password", "username", "totp", "notes"] {
            assert!(!text.contains(forbidden), "audit leaked {forbidden}");
        }
    }
}
