//! Bitwarden CLI adapter.
//!
//! Rules baked in here, not in callers:
//! * The master password only ever travels through an environment variable
//!   (`bw unlock --passwordenv`), never argv, so it cannot be read out of `ps`.
//! * The session key lives in memory only. It is never written to disk; the
//!   broker process is the only holder.
//! * `notes` is never parsed or returned, by construction — a recovery code
//!   sitting in a note must not be releasable to an agent.
//! * Every call has a timeout, because `bw` talks to the network on sync.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use tokio::process::Command;
use zeroize::Zeroizing;

const BW_TIMEOUT: Duration = Duration::from_secs(45);

/// A session key plus the moment it stops being honoured. Persisting the key is
/// off by default: the file *is* the vault key at rest, so enabling it is a
/// deliberate trade (no password after a restart, but root on this host can read
/// the vault). The expiry is stored absolute, so a restart can never extend an
/// unlock that the operator granted for an hour.
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedSession {
    session: String,
    expires_at: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn session_file(dir: &Path) -> PathBuf {
    dir.join("bw-session.json")
}

/// Is session persistence switched on for this process?
pub fn persist_enabled() -> bool {
    matches!(
        std::env::var("AAC_BROKER_PERSIST_SESSION").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}
const SESSION_ENV: &str = "BW_SESSION";
const PASSWORD_ENV: &str = "BW_PASSWORD";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    Unauthenticated,
    Locked,
    Unlocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub item_id: String,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uri: Option<String>,
}

#[derive(Deserialize)]
struct RawStatus {
    status: String,
}

fn parse_status(raw: &str) -> Option<VaultState> {
    let s: RawStatus = serde_json::from_str(raw).ok()?;
    match s.status.as_str() {
        "unauthenticated" => Some(VaultState::Unauthenticated),
        "locked" => Some(VaultState::Locked),
        "unlocked" => Some(VaultState::Unlocked),
        _ => None,
    }
}

#[derive(Deserialize)]
struct RawItem {
    id: String,
    name: String,
    #[serde(default)]
    login: Option<RawLogin>,
}

#[derive(Deserialize)]
struct RawLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<RawUri>,
}

#[derive(Deserialize)]
struct RawUri {
    #[serde(default)]
    uri: Option<String>,
}

fn to_candidate(item: &RawItem) -> Candidate {
    Candidate {
        id: item.id.clone(),
        name: item.name.clone(),
        username: item.login.as_ref().and_then(|l| l.username.clone()),
        uris: item
            .login
            .as_ref()
            .map(|l| l.uris.iter().filter_map(|u| u.uri.clone()).collect())
            .unwrap_or_default(),
    }
}

fn parse_candidates(raw: &str) -> Vec<Candidate> {
    serde_json::from_str::<Vec<RawItem>>(raw)
        .map(|items| items.iter().map(to_candidate).collect())
        .unwrap_or_default()
}

/// Parse one item into a releasable credential. `notes` is deliberately not in
/// `RawLogin`/`Credential`, so it cannot leak even if the JSON carries it.
fn parse_item(raw: &str) -> Option<Credential> {
    let item: RawItem = serde_json::from_str(raw).ok()?;
    let login = item.login;
    Some(Credential {
        item_id: item.id,
        name: item.name,
        username: login.as_ref().and_then(|l| l.username.clone()),
        password: login.as_ref().and_then(|l| l.password.clone()),
        totp: login.as_ref().and_then(|l| l.totp.clone()),
        uri: login
            .as_ref()
            .and_then(|l| l.uris.first())
            .and_then(|u| u.uri.clone()),
    })
}

pub struct Vault {
    bin: String,
    /// Session key, wrapped so its bytes are wiped when it is replaced or
    /// dropped. It still crosses into the child's environment as a `&str`,
    /// which is unavoidable for a subprocess call.
    session: std::sync::Mutex<Option<Zeroizing<String>>>,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            bin: "bw".to_string(),
            session: std::sync::Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub fn with_bin(bin: &str) -> Self {
        Self {
            bin: bin.to_string(),
            session: std::sync::Mutex::new(None),
        }
    }

    /// Test hook: pretend a session key is held, so the persistence codec can be
    /// exercised without running `bw unlock`.
    #[cfg(test)]
    pub fn set_session_for_test(&self, key: &str) {
        *self.session.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(Zeroizing::new(key.to_string()));
    }

    #[cfg(test)]
    pub fn is_unlocked(&self) -> bool {
        self.session
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
    }

    fn session(&self) -> Option<Zeroizing<String>> {
        self.session
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn clear_session(&self) {
        *self.session.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    async fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Result<String, String> {
        let mut cmd = Command::new(&self.bin);
        cmd.args(args)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let fut = cmd.output();
        let out = match tokio::time::timeout(BW_TIMEOUT, fut).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return Err(format!("spawn {}: {e}", self.bin)),
            Err(_) => return Err(format!("{} timed out after {BW_TIMEOUT:?}", args[0])),
        };
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).trim().to_string());
        }
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if err.is_empty() {
            format!("{} exited {}", args.join(" "), out.status)
        } else {
            err
        })
    }

    pub async fn status(&self) -> Result<VaultState, String> {
        let raw = self.run(&["status"], &[]).await?;
        parse_status(&raw).ok_or_else(|| "unrecognised bw status output".to_string())
    }

    /// Unlock with the master password held in an environment variable. The
    /// resulting session key is kept in memory only.
    pub async fn unlock(&self, master_password: &str) -> Result<(), String> {
        let raw = self
            .run(
                &["unlock", "--passwordenv", PASSWORD_ENV, "--raw"],
                &[(PASSWORD_ENV, master_password)],
            )
            .await?;
        if raw.is_empty() {
            return Err("bw unlock returned an empty session key".to_string());
        }
        *self.session.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(Zeroizing::new(raw));
        Ok(())
    }

    /// Write the live session key to disk with its absolute expiry. Only called
    /// when `persist_enabled()`, and only after a successful unlock.
    pub fn save_session(&self, dir: &Path, expires_at: u64) -> Result<(), String> {
        let session = self.session().ok_or("vault is locked")?;
        let body = serde_json::to_vec(&PersistedSession {
            session: session.to_string(),
            expires_at,
        })
        .map_err(|e| format!("serialize session: {e}"))?;
        let path = session_file(dir);
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| format!("open {}: {e}", tmp.display()))?;
            f.write_all(&body)
                .map_err(|e| format!("write session: {e}"))?;
            f.sync_all().map_err(|e| format!("sync session: {e}"))?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| format!("rename session: {e}"))
    }

    /// Load a persisted session and prove it still works before trusting it.
    /// Returns the expiry it was granted with, so the caller can restore exactly
    /// that window rather than inventing a fresh one.
    pub async fn restore_session(&self, dir: &Path) -> Result<u64, String> {
        let path = session_file(dir);
        let body = std::fs::read(&path).map_err(|e| format!("no persisted session: {e}"))?;
        let persisted: PersistedSession =
            serde_json::from_slice(&body).map_err(|e| format!("parse persisted session: {e}"))?;
        if persisted.expires_at <= now() {
            let _ = std::fs::remove_file(&path);
            return Err("persisted session had already expired; removed".to_string());
        }
        // Never trust a key because it is on disk: ask the vault.
        let raw = self
            .run(&["status"], &[(SESSION_ENV, &persisted.session)])
            .await?;
        match parse_status(&raw) {
            Some(VaultState::Unlocked) => {
                let expires_at = persisted.expires_at;
                *self.session.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some(Zeroizing::new(persisted.session));
                Ok(expires_at)
            }
            _ => {
                let _ = std::fs::remove_file(&path);
                Err("persisted session is no longer accepted by the vault".to_string())
            }
        }
    }

    /// Drop the persisted copy — on lock, on timeout, or on operator request.
    pub fn forget_session(&self, dir: &Path) {
        let _ = std::fs::remove_file(session_file(dir));
    }

    pub async fn lock(&self) -> Result<(), String> {
        let session = self.session();
        let result = match session {
            Some(s) => self.run(&["lock"], &[(SESSION_ENV, &s)]).await.map(|_| ()),
            None => Ok(()),
        };
        self.clear_session();
        result
    }

    /// Resolve a requested domain to candidate items. When `collection_id` is
    /// set the search never leaves that collection — "all domains" must not mean
    /// "the whole personal vault".
    pub async fn candidates(
        &self,
        domain: &str,
        collection_id: Option<&str>,
    ) -> Result<Vec<Candidate>, String> {
        let session = self.session().ok_or("vault is locked")?;
        let mut args: Vec<&str> = vec!["list", "items", "--search", domain];
        if let Some(cid) = collection_id {
            args.push("--collectionid");
            args.push(cid);
        }
        let raw = self.run(&args, &[(SESSION_ENV, &session)]).await?;
        Ok(parse_candidates(&raw))
    }

    /// Is this item inside the configured collection?
    ///
    /// `bw get item <id>` ignores collection scoping, so an id query — which is the one path that
    /// does not go through a scoped `--collectionid` search — could otherwise reach any item in the
    /// vault, including outside the collection the broker was told to serve.
    pub async fn item_in_collection(
        &self,
        item_id: &str,
        collection_id: &str,
    ) -> Result<bool, String> {
        let session = self.session().ok_or("vault is locked")?;
        let raw = self
            .run(
                &["list", "items", "--collectionid", collection_id],
                &[(SESSION_ENV, &session)],
            )
            .await?;
        Ok(parse_candidates(&raw).iter().any(|c| c.id == item_id))
    }

    /// Metadata for one item, for the approval card — no password is returned
    /// and none is parsed. Used when an agent asks by vault item id.
    pub async fn candidate_by_id(&self, item_id: &str) -> Result<Candidate, String> {
        let session = self.session().ok_or("vault is locked")?;
        let raw = self
            .run(&["get", "item", item_id], &[(SESSION_ENV, session.as_str())])
            .await?;
        let item: RawItem = serde_json::from_str(&raw)
            .map_err(|e| format!("item {item_id} did not parse: {e}"))?;
        Ok(to_candidate(&item))
    }

    /// Fetch one item by id. Only the fields in `Credential` survive parsing.
    pub async fn credential(&self, item_id: &str) -> Result<Credential, String> {
        let session = self.session().ok_or("vault is locked")?;
        let raw = self
            .run(&["get", "item", item_id], &[(SESSION_ENV, &session)])
            .await?;
        parse_item(&raw).ok_or_else(|| format!("item {item_id} did not parse"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS_LOCKED: &str = r#"{"serverUrl":null,"userEmail":"a@b.c","status":"locked","lastSync":"2026-10-23T10:58:11.551Z"}"#;
    const STATUS_UNLOCKED: &str = r#"{"status":"unlocked"}"#;

    const ITEM: &str = r#"{
        "id": "11111111-2222-3333-4444-555555555555",
        "name": "GitHub",
        "notes": "recovery codes: DONOTLEAK",
        "login": {
            "username": "agent@example.com",
            "password": "s3cret",
            "totp": "JBSWY3DPEHPK3PXP",
            "uris": [{"uri": "https://github.com"}, {"uri": "https://gist.github.com"}]
        },
        "fields": [{"name": "extra", "value": "alsonotleaking"}]
    }"#;

    #[test]
    fn status_parses_all_three_states() {
        assert_eq!(parse_status(STATUS_LOCKED), Some(VaultState::Locked));
        assert_eq!(parse_status(STATUS_UNLOCKED), Some(VaultState::Unlocked));
        assert_eq!(
            parse_status(r#"{"status":"unauthenticated"}"#),
            Some(VaultState::Unauthenticated)
        );
        assert_eq!(parse_status("not json"), None);
    }

    #[test]
    fn item_parses_releasable_fields_only() {
        let c = parse_item(ITEM).expect("parse");
        assert_eq!(c.name, "GitHub");
        assert_eq!(c.username.as_deref(), Some("agent@example.com"));
        assert_eq!(c.password.as_deref(), Some("s3cret"));
        assert_eq!(c.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(c.uri.as_deref(), Some("https://github.com"));
    }

    #[test]
    fn notes_and_custom_fields_can_never_be_released() {
        // The struct has no field to carry them: prove it by checking the
        // serialised shape of a parsed credential contains no trace of them.
        let c = parse_item(ITEM).expect("parse");
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("DONOTLEAK"));
        assert!(!rendered.contains("alsonotleaking"));
        assert!(!rendered.contains("recovery"));
    }

    fn fake_bw(tag: &str, body: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "aac-vault-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let bin = dir.join("bw");
        let mut f = std::fs::File::create(&bin).expect("create");
        writeln!(f, "#!/bin/sh\ncat <<'EOF'\n{body}\nEOF").expect("write");
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        (dir, bin)
    }

    #[test]
    fn a_persisted_session_is_written_0600_with_an_absolute_expiry() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, _bin) = fake_bw("persist", "{}");
        let v = Vault::new();
        v.set_session_for_test("session-key-123");
        v.save_session(&dir, 1_900_000_000).expect("save");

        let path = session_file(&dir);
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the session key must not be world readable");
        let body = std::fs::read_to_string(&path).expect("read");
        assert!(body.contains("1900000000"), "expiry is stored, not recomputed");
        assert!(body.contains("session-key-123"));
    }

    #[tokio::test]
    async fn an_expired_persisted_session_is_discarded_without_asking_the_vault() {
        let (dir, bin) = fake_bw("expired", "{\"status\":\"unlocked\"}");
        let saver = Vault::with_bin(bin.to_str().expect("path"));
        saver.set_session_for_test("session-key-456");
        saver.save_session(&dir, 1).expect("save"); // already in the past

        // A fresh process: nothing in memory, only the file on disk.
        let fresh = Vault::with_bin(bin.to_str().expect("path"));
        assert!(fresh.restore_session(&dir).await.is_err());
        assert!(
            !session_file(&dir).exists(),
            "an expired session file must be removed, not left for a retry"
        );
        assert!(!fresh.is_unlocked(), "an expired key must not unlock anything");
    }

    #[tokio::test]
    async fn a_persisted_session_the_vault_rejects_is_discarded() {
        let (dir, bin) = fake_bw("rejected", "{\"status\":\"locked\"}");
        let saver = Vault::with_bin(bin.to_str().expect("path"));
        saver.set_session_for_test("session-key-789");
        saver.save_session(&dir, 4_000_000_000).expect("save");

        let fresh = Vault::with_bin(bin.to_str().expect("path"));
        assert!(fresh.restore_session(&dir).await.is_err());
        assert!(!session_file(&dir).exists(), "a rejected key is not kept");
        assert!(!fresh.is_unlocked());
    }

    #[tokio::test]
    async fn a_persisted_session_the_vault_accepts_keeps_its_original_expiry() {
        let (dir, bin) = fake_bw("restore", "{\"status\":\"unlocked\"}");
        let v = Vault::with_bin(bin.to_str().expect("path"));
        v.set_session_for_test("session-key-abc");
        let granted = 4_000_000_000u64;
        v.save_session(&dir, granted).expect("save");

        let v2 = Vault::with_bin(bin.to_str().expect("path"));
        let restored = v2.restore_session(&dir).await.expect("restore");
        assert_eq!(restored, granted, "the window is restored, never extended");
        assert!(v2.is_unlocked());
        assert!(session_file(&dir).exists(), "a valid session stays on disk");
    }

    #[test]
    fn candidates_parse_and_keep_ids() {
        let raw = format!("[{ITEM}]");
        let c = parse_candidates(&raw);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].name, "GitHub");
        assert_eq!(c[0].uris.len(), 2);
        assert_eq!(c[0].id, "11111111-2222-3333-4444-555555555555");
    }

    #[test]
    fn empty_or_junk_list_is_empty_not_panic() {
        assert!(parse_candidates("[]").is_empty());
        assert!(parse_candidates("garbage").is_empty());
        assert!(parse_item("garbage").is_none());
    }

    #[tokio::test]
    async fn locked_vault_refuses_lookups_without_shelling_out() {
        let v = Vault::with_bin("/nonexistent/bw");
        assert!(!v.is_unlocked());
        assert_eq!(v.candidates("github.com", None).await, Err("vault is locked".to_string()));
        assert_eq!(
            v.credential("abc").await,
            Err("vault is locked".to_string())
        );
    }
}
