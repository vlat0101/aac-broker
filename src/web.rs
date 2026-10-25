//! The approval surface.
//!
//! Bound to 127.0.0.1 and published on the tailnet by `tailscale serve`.
//!
//! **Authentication is the identity `tailscale serve` injects**
//! (`Tailscale-User-Login`, trusted only alongside `X-Forwarded-For`, which rejects a raw local
//! request trying to set the header itself), and that identity must equal `AAC_BROKER_OWNER`.
//! Tagged devices receive no identity header at all, so an agent host cannot approve its own
//! request. The bearer-token path (`AAC_BROKER_ALLOW_TOKEN` + `AAC_BROKER_TOKEN`) is a break-glass
//! second mechanism, off by default.
//!
//! Every state-changing POST also checks `origin_ok`, which compares the request's host and origin
//! against `AAC_BROKER_HOST`: an authorised request from the operator's own browser is still a
//! cross-site request if a page somewhere else made it.
//!
//! Everything the page shows about a request is labelled verified or claimed — an agent controls
//! half of it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

use crate::audit::{Audit, Entry};
use crate::pending::{Choice, Pending};
use crate::policy::Grants;
use crate::push::Pushover;
use crate::vault::Vault;
use ap_client::CredentialQuery;
use crate::storage::FileConnections;

const COOKIE: &str = "aac";
const COOKIE_MAX_AGE: u64 = 30 * 86_400;
/// Unlock attempts allowed inside `UNLOCK_WINDOW` before the page stops
/// accepting master-password guesses.
const UNLOCK_ATTEMPTS: usize = 5;
const UNLOCK_WINDOW: Duration = Duration::from_secs(600);
const UNLOCK_PENALTY: Duration = Duration::from_secs(600);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub struct AppState {
    /// State directory: identity, connections, grants, audit.
    pub dir: std::path::PathBuf,
    /// Collection the vault lookups are confined to, when configured. The page
    /// resolves held requests with the same scope the service uses.
    pub collection: Option<String>,
    pub vault: Arc<Vault>,
    pub pending: Arc<Pending>,
    pub grants: Arc<Grants>,
    pub audit: Arc<Audit>,
    pub push: Option<Pushover>,
    /// Epoch seconds at which the vault locks itself again. 0 = locked.
    pub unlock_until: AtomicU64,
    /// Host the page is served on, for the same-origin check on POSTs.
    pub expected_host: String,
    /// Serialises unlock attempts so two form posts cannot race the CLI.
    /// Tokio mutex: the guard is held across the `bw unlock` await.
    pub unlock_lock: tokio::sync::Mutex<()>,
    /// Tailscale login that is allowed to act as the operator. Serve injects
    /// `Tailscale-User-Login` for user-owned devices and strips any value the
    /// client supplies, so this is a verified identity — not a shared secret.
    pub owner: String,
    /// Break-glass bearer token, honoured only when explicitly enabled. Kept so
    /// an auth outage cannot lock the operator out of their own broker.
    pub token: String,
    pub allow_token: bool,
    /// Failed unlock attempts, newest last, for rate limiting.
    pub unlock_failures: std::sync::Mutex<Vec<Instant>>,
    /// Ask the service loop for a rendezvous code (it owns the relay client).
    /// Pair requests carry a reply channel: the page waits for the relay's code
    /// instead of assuming one was produced.
    pub pair_tx: tokio::sync::mpsc::Sender<(
        String,
        tokio::sync::oneshot::Sender<Result<String, String>>,
    )>,
    /// Armed pairing name, consumed by the next fingerprint verification.
    pub pair_arm: std::sync::Mutex<Option<(String, Instant)>>,
    /// Most recent pairing code: (name, code, issued at).
    pub pair_code: std::sync::Mutex<Option<(String, String, Instant)>>,
    /// Revocation requests handled by the service loop, which owns the relay
    /// client: the store must only be edited while that client is stopped.
    pub revoke_tx: tokio::sync::mpsc::Sender<(
        String,
        tokio::sync::oneshot::Sender<Result<usize, String>>,
    )>,
}

/// How long a pairing code stays usable (the relay's own TTL).
pub const PAIR_WINDOW: Duration = Duration::from_secs(300);

fn clean_name(s: &str) -> Option<String> {
    let out: String = s
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(32)
        .collect();
    (!out.is_empty()).then_some(out)
}

/// Length-independent comparison: a token check must not leak its prefix
/// through timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix(&format!("{COOKIE}=")) {
            return Some(v.to_string());
        }
    }
    None
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

impl AppState {
    pub fn unlocked(&self) -> bool {
        self.unlock_until.load(Ordering::Relaxed) > now()
    }

    /// Identity of the caller, as asserted by Tailscale Serve. `X-Forwarded-For`
    /// must be present: Serve always sets it, so requiring it rejects a raw
    /// local request that tries to supply the header itself.
    pub fn tailnet_identity(&self, headers: &HeaderMap) -> Option<String> {
        let login = headers.get("tailscale-user-login").and_then(|v| v.to_str().ok())?;
        headers.get("x-forwarded-for")?;
        Some(login.to_string())
    }

    pub fn authorised(&self, headers: &HeaderMap) -> bool {
        if self
            .tailnet_identity(headers)
            .is_some_and(|who| who.eq_ignore_ascii_case(&self.owner))
        {
            return true;
        }
        if !self.allow_token {
            return false;
        }
        bearer_token(headers)
            .or_else(|| cookie_token(headers))
            .is_some_and(|t| ct_eq(t.as_bytes(), self.token.as_bytes()))
    }

    /// Who approved, for the audit line. Prefers the verified tailnet identity.
    fn actor(&self, headers: &HeaderMap) -> String {
        match self.tailnet_identity(headers) {
            Some(who) => who,
            None => "break-glass token".to_string(),
        }
    }

    /// Record a failed unlock and report whether the caller is now locked out.
    fn note_unlock_failure(&self) -> bool {
        let mut fails = self.unlock_failures.lock().unwrap_or_else(|p| p.into_inner());
        fails.push(Instant::now());
        fails.retain(|t| t.elapsed() < UNLOCK_WINDOW);
        fails.len() >= UNLOCK_ATTEMPTS
    }

    fn unlock_penalty_active(&self) -> bool {
        let mut fails = self.unlock_failures.lock().unwrap_or_else(|p| p.into_inner());
        fails.retain(|t| t.elapsed() < UNLOCK_PENALTY);
        fails.len() >= UNLOCK_ATTEMPTS
    }

    fn clear_unlock_failures(&self) {
        self.unlock_failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }
}

fn esc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c if c.is_control() => String::new(),
            c => c.to_string(),
        })
        .collect()
}

/// Epoch seconds as a short UTC date, or "never" for 0.
fn when(ts: u64) -> String {
    if ts == 0 {
        return "never".to_string();
    }
    let days = ts / 86_400;
    let secs = ts % 86_400;
    // Civil date from days since the epoch (Howard Hinnant's algorithm), so the
    // page needs no date library.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60
    )
}

fn age(created: Instant) -> String {
    let s = created.elapsed().as_secs();
    if s < 60 {
        format!("{s}s")
    } else {
        format!("{}m{:02}s", s / 60, s % 60)
    }
}

fn short(fp: &str) -> String {
    fp.chars().take(12).collect()
}

/// A browser sends `Origin` on a form POST. A mismatched origin is refused;
/// an absent one is fine here because the bearer token is the real gate and
/// non-browser clients (`curl` on the box) do not send it.
fn origin_ok(headers: &HeaderMap, expected_host: &str) -> bool {
    match headers.get("origin").and_then(|v| v.to_str().ok()) {
        None => true,
        Some(o) => {
            let host = o
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            host.split('/').next() == Some(expected_host)
        }
    }
}

fn denied(msg: &str) -> Response {
    (StatusCode::UNAUTHORIZED, Html(format!("<p>{}</p>", esc(msg)))).into_response()
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(|| async { "ok" }))
        .route("/unlock", post(unlock))
        .route("/lock", post(lock))
        .route("/decision", post(decision))
        .route("/grant/revoke", post(revoke))
        .route("/pair", post(pair))
        .route("/pair/cancel", post(cancel_pair))
        .route("/device/revoke", post(revoke_device))
        .with_state(state)
}

#[derive(Deserialize)]
struct BootQuery {
    k: Option<String>,
    /// Flash message after a post-redirect-get, e.g. `approved`.
    msg: Option<String>,
    /// Activity log page, 1-based.
    page: Option<usize>,
}

async fn index(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<BootQuery>,
) -> Response {
    // Bootstrap: `/?k=<token>` sets the cookie once, then the URL is clean.
    // Bookmarks and push notifications therefore never carry the token.
    if let Some(k) = q.k.as_deref() {
        if st.allow_token && ct_eq(k.as_bytes(), st.token.as_bytes()) {
            let cookie = format!(
                "{COOKIE}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={COOKIE_MAX_AGE}",
                st.token
            );
            return (
                StatusCode::SEE_OTHER,
                [
                    (header::SET_COOKIE, cookie),
                    (header::LOCATION, "/".to_string()),
                ],
                Html(String::new()),
            )
                .into_response();
        }
        return denied("bad token");
    }
    if !st.authorised(&headers) {
        return denied(
            "not authorised: open this page from your own tailnet device \
             (Tailscale identity is required), or enable the break-glass token",
        );
    }
    Html(render(&st, q.msg.as_deref(), q.page.unwrap_or(1))).into_response()
}

/// Post-redirect-get target: a real 303 so the browser lands back on the page
/// with a message instead of showing a half-rendered redirect body.
fn see_other(msg: &str) -> Response {
    let location = format!("/?msg={msg}");
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location)],
        Html(String::new()),
    )
        .into_response()
}

fn banner(msg: Option<&str>) -> String {
    let (class, text) = match msg {
        Some("approved") => ("banner ok", "Approved — the credential was released."),
        Some("approved-forever") => (
            "banner ok",
            "Approved permanently — this agent will not ask for that site again (revoke it under the device).",
        ),
        Some("denied") => ("banner no", "Denied — the agent gets a refusal."),
        Some("gone") => (
            "banner warn",
            "That request had already timed out or been decided.",
        ),
        Some("unlocked") => ("banner ok", "Vault unlocked."),
        Some("locked") => ("banner ok", "Vault locked."),
        Some("pair") => ("banner ok", "Pairing code issued — it is below, valid for 5 minutes."),
        Some("pair-failed") => (
            "banner no",
            "No pairing code: the relay did not answer. Check the service and try again.",
        ),
        Some("pair-cancelled") => (
            "banner ok",
            "Pairing cancelled. That code can no longer pair anything with this broker.",
        ),
        Some("pair-none") => ("banner warn", "There was no pending pairing code."),
        Some("nopick") => ("banner warn", "Nothing approved — pick which item first."),
        Some("revoked") => ("banner ok", "Remembered approval revoked."),
        Some("revoke-failed") => (
            "banner warn",
            "That approval was NOT revoked: the grants file could not be written. It is still in \
             place and will load again on the next start — fix the state directory permissions.",
        ),
        Some("grant-failed") => (
            "banner warn",
            "Approved, but the grant could NOT be saved, so nothing was remembered. The credential \
             was not released. Check the state directory permissions, then approve again.",
        ),
        Some("unpaired") => (
            "banner ok",
            "Device unpaired. The relay link restarts and that host must pair again.",
        ),
        Some("unpair-failed") => (
            "banner no",
            "Could not unpair that device — nothing was removed.",
        ),
        _ => return String::new(),
    };
    format!(r#"<div class="{class}">{text}</div>"#, class = class, text = text)
}

/// Entries per page in the activity log.
const PER_PAGE: usize = 25;

fn render(st: &AppState, msg: Option<&str>, page: usize) -> String {
    let unlocked = st.unlocked();
    let until = st.unlock_until.load(Ordering::Relaxed);
    let pending = st.pending.list();
    let page = page.max(1);
    let (entries, total) = st.audit.page(page, PER_PAGE);
    let pages = total.div_ceil(PER_PAGE).max(1);

    let mut pending_html = String::new();
    if pending.is_empty() {
        pending_html.push_str("<p class=\"empty\">Nothing waiting.</p>");
    }
    for p in &pending {
        // Held because the vault was locked: nothing to name yet, so offer the
        // unlock right here rather than denying and making the agent ask again.
        if p.locked {
            pending_html.push_str(&format!(
                r#"<article class="req locked">
  <div class="who"><strong>{device}</strong> <span class="tag verified">verified · {fp}</span></div>
  <div class="claim">{agent} <span class="tag claimed">agent, claimed</span></div>
  <div class="asked">asked for <code>{requested}</code> · waiting {age}</div>
  {reason}
  <div class="vault shut"><span class="dot"></span> Vault is locked — unlock to see which login this is</div>
  <form method="post" action="/unlock">
    <input class="vh" type="text" name="username" value="{owner}" autocomplete="username"
           tabindex="-1" aria-hidden="true">
    <input type="password" name="password" placeholder="master password" required
           autocomplete="current-password" autocapitalize="off" autocorrect="off"
           spellcheck="false" enterkeyhint="go">
    <select name="ttl">
      <option value="3600">1h</option><option value="7200" selected>2h</option>
      <option value="14400">4h</option><option value="28800">8h</option>
    </select>
    <button class="ok">Unlock and resolve</button>
  </form>
  <form method="post" action="/decision" class="inline">
    <input type="hidden" name="id" value="{id}">
    <button name="choice" value="deny" class="no">Deny</button>
  </form>
</article>"#,
                device = esc(&p.device),
                fp = esc(&short(&p.fingerprint)),
                agent = p
                    .agent_claim
                    .as_deref()
                    .map_or("<em>unnamed agent</em>".to_string(), esc),
                requested = esc(&p.requested),
                age = age(p.created),
                owner = esc(&st.owner),
                reason = p
                    .reason
                    .as_deref()
                    .map_or(String::new(), |r| format!("<div class=\"why\">{}</div>", esc(r))),
                id = esc(&p.id),
            ));
            continue;
        }
        // One match: straight to approve. Several: the operator picks which
        // item leaves, because only a human can tell two logins for the same
        // host apart. Nothing is ever released as a set.
        let picker = if p.items.len() == 1 {
            let item = &p.items[0];
            let wanted = crate::host_of(&p.requested);
            let note = if item.uris.iter().any(|u| crate::host_of(u) == wanted) {
                String::new()
            } else {
                format!(
                    r#"<div class="note">no exact host match for <code>{}</code> — this is what the vault returned</div>"#,
                    esc(&p.requested)
                )
            };
            format!(
                r#"{note}<div class="what">wants <strong>{item}</strong>{user}</div>
    <div class="puri">{uri}</div>
    <input type="hidden" name="item" value="{item_id}">"#,
                item = esc(&item.name),
                user = item
                    .username
                    .as_deref()
                    .map_or(String::new(), |u| format!(" ({})", esc(u))),
                uri = esc(item.uris.first().map(String::as_str).unwrap_or("(no uri)")),
                item_id = esc(&item.id),
            )
        } else {
            let mut rows = String::new();
            let wanted = crate::host_of(&p.requested);
            let any_exact = p
                .items
                .iter()
                .any(|i| i.uris.iter().any(|u| crate::host_of(u) == wanted));
            let picknote = if any_exact {
                String::new()
            } else {
                format!(
                    r#"<div class="note">no exact host match for <code>{}</code> — these are what the vault returned, best first</div>"#,
                    esc(&p.requested)
                )
            };
            for (n, item) in p.items.iter().enumerate() {
                // Say why an item is on the list: the vault search is a substring
                // match, so a host that does not match exactly is still offered —
                // the operator decides, but they should see which is which.
                let exact = item.uris.iter().any(|u| crate::host_of(u) == wanted);
                let tag = if exact {
                    String::new()
                } else {
                    "<span class=\"tag similar\">similar</span>".to_string()
                };
                rows.push_str(&format!(
                    r#"<label class="pick"><input type="radio" name="item" value="{id}"{checked}>
      <span class="pname">{name}</span>{user}{tag}
      <span class="puri">{uri}</span></label>"#,
                    id = esc(&item.id),
                    // Pre-checking the first row is how a `com.au`-style near-match becomes the
                    // default approval. Only a row whose host matches the request exactly may be
                    // pre-selected; everything else needs a deliberate tap.
                    checked = if n == 0 && exact { " checked" } else { "" },
                    name = esc(&item.name),
                    user = item
                        .username
                        .as_deref()
                        .map_or(String::new(), |u| format!(" <span class=\"muted\">({})</span>", esc(u))),
                    uri = esc(item.uris.first().map(String::as_str).unwrap_or("(no uri)")),
                ));
            }
            format!(
                r#"{picknote}<div class="what">asked for <strong>{host}</strong> — {n} entries match. Pick one:</div>
    {rows}"#,
                host = esc(&p.requested),
                n = p.items.len(),
                picknote = picknote,
            )
        };

        pending_html.push_str(&format!(
            r#"<article class="req">
  <div class="who"><strong>{device}</strong> <span class="tag verified">verified · {fp}</span></div>
  <div class="claim">{agent} <span class="tag claimed">agent, claimed</span></div>
  <div class="asked">asked for <code>{requested}</code> · waiting {age}</div>
  {reason}
  <form method="post" action="/decision">
    <input type="hidden" name="id" value="{id}">
    {picker}
    <button name="choice" value="approve" class="ok">Approve</button>
    <button name="choice" value="deny" class="no">Deny</button>
    <label class="remember">remember
      <select name="remember">
        <option value="0">this once</option>
        <option value="900">15 min</option>
        <option value="3600">1 hour</option>
        <option value="forever">always — permanent</option>
      </select>
    </label>
  </form>
</article>"#,
            device = esc(&p.device),
            fp = esc(&short(&p.fingerprint)),
            agent = p
                .agent_claim
                .as_deref()
                .map_or("<em>unnamed agent</em>".to_string(), esc),
            picker = picker,
            reason = p
                .reason
                .as_deref()
                .map_or(String::new(), |r| format!("<div class=\"why\">{}</div>", esc(r))),
            requested = esc(&p.requested),
            age = age(p.created),
            id = esc(&p.id),
        ));
    }

    // Paired devices: who is allowed to ask at all. Read from the connection
    // store the relay client persists, so this is the same data the protocol
    // uses to accept a session.
    let mut devices_html = String::new();
    let mut device_count = 0usize;
    match FileConnections::load(&st.dir) {
        Ok(conns) => {
            let mut devices = conns.devices();
            devices.sort_by_key(|d| d.paired_at);
            if devices.is_empty() {
                devices_html.push_str("<p class=\"empty\">No devices paired.</p>");
            }
            device_count = devices.len();
            for d in devices {
                let fp: String = d.fingerprint.chars().take(12).collect();
                // Approvals are shown under the device they belong to: an
                // approval is a statement about one agent, not a global list.
                let mine = st.grants.for_agent(&d.fingerprint);
                let mut rows = String::new();
                for g in &mine {
                    let left = if g.permanent {
                        r#"<span class="tag perm">permanent</span>"#.to_string()
                    } else {
                        let mins = g.expires_at.saturating_sub(now()) / 60;
                        format!(r#"<span class="tag soon">{} min left</span>"#, mins)
                    };
                    let site = match g.domain.as_deref() {
                        Some(dm) if !dm.is_empty() => {
                            format!(r#"<span class="site">{}</span> → "#, esc(dm))
                        }
                        _ => String::new(),
                    };
                    rows.push_str(&format!(
                        r#"<li>{site}{item} {left}
<form method="post" action="/grant/revoke" class="inline">
<input type="hidden" name="fingerprint" value="{fpf}">
<input type="hidden" name="item_id" value="{id}">
<button class="link">revoke</button></form></li>"#,
                        site = site,
                        item = esc(&g.item_name),
                        left = left,
                        fpf = esc(&g.fingerprint),
                        id = esc(&g.item_id),
                    ));
                }
                if mine.is_empty() {
                    rows.push_str(
                        r#"<li class="empty">nothing approved — every request asks first</li>"#,
                    );
                }
                let n = mine.len();
                devices_html.push_str(&format!(
                    r#"<details class="dev">
<summary><strong>{name}</strong> <span class="fp">{fp}</span>
<span class="muted">paired {paired} · last used {used} · {n} approval(s)</span></summary>
<div class="devbody">
<ul class="grants">{rows}</ul>
<p class="fp full">{full_fp}</p>
<form method="post" action="/device/revoke" class="inline">
  <input type="hidden" name="fingerprint" value="{full_fp}">
  <label class="confirm"><input type="checkbox" name="confirm" value="yes" required> unpair</label>
  <button class="no" type="submit">Unpair</button>
</form>
</div></details>"#,
                    name = esc(&d.name),
                    fp = esc(&fp),
                    full_fp = esc(&d.fingerprint),
                    paired = when(d.paired_at),
                    used = when(d.last_connected_at),
                    rows = rows,
                    n = n,
                ));
            }
        }
        Err(e) => devices_html.push_str(&format!(
            "<p class=\"empty\">Could not read the connection store: {}</p>",
            esc(&e.to_string())
        )),
    }

    // Activity log: newest first, one page at a time, every line clickable for
    // the whole record. Times are epochs in the file; the page shows local time
    // (rendered here as UTC, then rewritten by the browser to its own zone).
    let mut audit_html = String::new();
    if entries.is_empty() {
        audit_html.push_str("<p class=\"empty\">No activity recorded.</p>");
    }
    for e in &entries {
        let ts = e.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
        let kind = e.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
        let outcome = e.get("outcome").and_then(|v| v.as_str()).unwrap_or("");
        let device = e.get("device").and_then(|v| v.as_str()).unwrap_or("");
        let item = e.get("item_name").and_then(|v| v.as_str()).unwrap_or("");
        let agent = e.get("agent").and_then(|v| v.as_str()).unwrap_or("");
        let requested = e.get("requested").and_then(|v| v.as_str()).unwrap_or("");
        // Every remaining field, so the drill-down is the record, not a summary.
        let mut detail = String::new();
        if let Some(obj) = e.as_object() {
            for (k, v) in obj {
                if k == "ts" {
                    continue;
                }
                let text = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                detail.push_str(&format!(
                    "<div class=\"kv\"><span class=\"k\">{}</span><span class=\"v\">{}</span></div>",
                    esc(k),
                    esc(&text)
                ));
            }
        }
        audit_html.push_str(&format!(
            r#"<details class="logrow">
<summary>
  <span class="c-when" data-ts="{ts}">{when}</span>
  <span class="c-kind">{kind}</span>
  <span class="c-who">{device}{agent_part}</span>
  <span class="c-item">{item}{req_part}</span>
  <span class="c-out o-{outcome}">{outcome}</span>
</summary>
<div class="logdetail">{detail}</div>
</details>"#,
            ts = ts,
            when = esc(&when(ts)),
            kind = esc(kind),
            device = esc(device),
            agent_part = if agent.is_empty() {
                String::new()
            } else {
                format!(" · <span class=\"muted\">{}</span>", esc(agent))
            },
            item = esc(item),
            req_part = if requested.is_empty() || requested == item {
                String::new()
            } else {
                format!(" <span class=\"muted\">({})</span>", esc(requested))
            },
            outcome = esc(outcome),
            detail = detail,
        ));
    }

    let pager = format!(
        r#"<div class="pager">
{newer}
<span class="muted">page {page} of {pages} · {total} entries</span>
{older}
</div>"#,
        newer = if page > 1 {
            format!(r#"<a href="/?page={}#activity">‹ newer</a>"#, page - 1)
        } else {
            r#"<span class="muted">‹ newer</span>"#.to_string()
        },
        older = if page < pages {
            format!(r#"<a href="/?page={}#activity">older ›</a>"#, page + 1)
        } else {
            r#"<span class="muted">older ›</span>"#.to_string()
        },
        page = page,
        pages = pages,
        total = total,
    );

    let vault_block = if unlocked {
        let left = until.saturating_sub(now());
        let lockout = if st.unlock_penalty_active() {
            " <span class=\"muted\">(unlock locked out after repeated failures)</span>"
        } else {
            ""
        };
        format!(
            r#"<div class="vault open">
  <span class="dot"></span> Vault unlocked — locks in {m} min{lockout}
  <form method="post" action="/lock" class="inline"><button class="no">Lock now</button></form>
</div>"#,
            m = left / 60
        )
    } else {
        format!(
            r#"<div class="vault shut">
  <span class="dot"></span> Vault locked — held requests wait for you
  <form method="post" action="/unlock" class="unlock">
    <input class="vh" type="text" name="username" value="{owner}" autocomplete="username"
           tabindex="-1" aria-hidden="true">
    <input type="password" name="password" placeholder="Master password" required
           autocomplete="current-password" autocapitalize="off" autocorrect="off"
           spellcheck="false" enterkeyhint="go">
    <select name="ttl">
      <option value="3600">1 hour</option>
      <option value="7200" selected>2 hours</option>
      <option value="14400">4 hours</option>
      <option value="28800">8 hours</option>
    </select>
    <button class="ok">Unlock</button>
  </form>
</div>"#,
            owner = esc(&st.owner)
        )
    };

    let pair_block = {
        let held = st.pair_code.lock().unwrap_or_else(|p| p.into_inner()).clone();
        match held {
            Some((name, code, at)) if at.elapsed() < PAIR_WINDOW => format!(
                r#"<div class="pair"><div>Pairing code for <strong>{name}</strong></div>
<div class="coderow">
  <span class="code" id="paircode">{code}</span>
  <button class="copy" type="button" data-copy="{code_attr}" aria-label="Copy pairing code" title="Copy to clipboard">
    <svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true" fill="none"
         stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <rect x="9" y="9" width="12" height="12" rx="2"></rect>
      <path d="M5 15V5a2 2 0 0 1 2-2h10"></path>
    </svg>
    <span class="copylabel">copy</span>
  </button>
</div>
<div class="muted">On that host, once: <code>aac connect --token {code}</code> &middot;
valid {left}s &middot; single use</div>
<div class="pairbtns">
  <form method="post" action="/pair">
    <input type="hidden" name="name" value="{name}">
    <button class="link">reissue</button>
  </form>
  <form method="post" action="/pair/cancel">
    <button class="no">cancel code</button>
  </form>
</div></div>"#,
                name = esc(&name),
                code = esc(&code),
                code_attr = esc(&code),
                left = PAIR_WINDOW.as_secs().saturating_sub(at.elapsed().as_secs()),
            ),
            Some((name, _, at)) => format!(
                r#"<details class="pair" open><summary>The code for <strong>{name}</strong> expired {mins} min ago</summary>
<div class="pairbtns">
  <form method="post" action="/pair">
    <input type="hidden" name="name" value="{name}">
    <button class="ok">Get a new code</button>
  </form>
  <form method="post" action="/pair/cancel">
    <button class="link">clear</button>
  </form>
</div></details>"#,
                name = esc(&name),
                mins = at.elapsed().as_secs() / 60,
            ),
            _ => r#"<details class="pair"><summary>Pair a device</summary>
<form method="post" action="/pair">
  <input name="name" placeholder="device name, e.g. codex-host" required maxlength="32">
  <button class="ok">Get pairing code</button>
</form>
<div class="muted">The agent host connects to the same relay and uses the code within 5 minutes.</div></details>"#
                .to_string(),
        }
    };

    format!(
        r#"<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>aac-broker</title>
<style>
:root{{color-scheme:dark}}
*{{box-sizing:border-box}}
body{{margin:0 auto;max-width:44rem;padding:1.25rem;background:#11141a;color:#e6e9ef;
 font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}}
h1{{font-size:1.1rem;margin:0 0 1rem;letter-spacing:.02em}}
h2{{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;color:#8b93a7;margin:1.75rem 0 .6rem}}
.vault{{display:flex;flex-wrap:wrap;gap:.6rem;align-items:center;padding:.7rem .9rem;border-radius:.5rem;font-size:.9rem}}
.open{{background:#12301d;border:1px solid #235c37}} .shut{{background:#2e1a1a;border:1px solid #5c2626}}
.dot{{width:.55rem;height:.55rem;border-radius:50%;background:#41c46b}} .shut .dot{{background:#e05353}}
form{{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin:0}}
form.unlock,input,select,button{{font:inherit}}
input,select{{background:#1b1f27;border:1px solid #2c3341;color:#e6e9ef;border-radius:.4rem;padding:.45rem .6rem}}
input[type=password]{{min-width:14rem}}
button{{border:0;border-radius:.4rem;padding:.5rem .9rem;cursor:pointer;font-weight:600}}
.ok{{background:#1f7a45;color:#fff}} .no{{background:#7a2626;color:#fff}}
button.link{{background:none;color:#8b93a7;text-decoration:underline;padding:0 .2rem;font-size:.8rem}}
.req{{border:1px solid #2c3341;border-radius:.6rem;padding:.85rem;margin:.6rem 0;background:#171b23}}
.who{{font-size:1rem}} .claim{{color:#c8b06a;font-size:.85rem;margin-top:.15rem}}
.what{{margin:.5rem 0}} .why{{color:#9aa3b5;font-size:.85rem}}
.asked{{color:#6f7789;font-size:.75rem;margin:.35rem 0 .6rem;font-family:ui-monospace,monospace}}
.tag{{font-size:.65rem;padding:.1rem .4rem;border-radius:.25rem;vertical-align:middle}}
.verified{{background:#12301d;color:#5fd68d;border:1px solid #235c37}}
.claimed{{background:#2e2718;color:#c8b06a;border:1px solid #5c4a26}}
label.remember{{color:#8b93a7;font-size:.8rem;margin-left:auto}}
.empty{{color:#6f7789;font-size:.85rem}}
ul{{list-style:none;padding:0;margin:0}} li{{padding:.35rem 0;border-bottom:1px solid #1e232c;font-size:.85rem;display:flex;gap:.5rem;align-items:center}}
.muted{{color:#6f7789}}
table{{width:100%;border-collapse:collapse;font-size:.78rem}}
td{{padding:.2rem .4rem;border-bottom:1px solid #1e232c}} .o-allowed{{color:#5fd68d}} .o-denied,.o-timeout{{color:#e05353}}
form.inline{{margin-left:auto}}
.pair{{margin:1rem 0;padding:.7rem .9rem;border:1px solid #2c3341;border-radius:.5rem;background:#171b23;font-size:.88rem}}
.pair summary{{cursor:pointer;color:#9aa3b5}}
.coderow{{display:flex;align-items:center;gap:.7rem;margin:.4rem 0}}
.pairbtns{{display:flex;gap:.8rem;align-items:center;margin-top:.35rem}}
.pairbtns form{{margin:0}}
.code{{font-family:ui-monospace,monospace;font-size:1.25rem;letter-spacing:.12em;color:#5fd68d;-webkit-user-select:all;user-select:all}}
button.copy{{display:inline-flex;align-items:center;gap:.35rem;background:#1d2430;border:1px solid #2f3a4b;color:#9fb0c7;border-radius:.4rem;padding:.3rem .5rem;font-size:.74rem;cursor:pointer;line-height:1}}
button.copy:hover{{background:#243044;color:#cfd6e4}}
button.copy:active{{transform:translateY(1px)}}
button.copy svg{{flex:none}}
label.pick{{display:flex;flex-direction:column;gap:.15rem;padding:.5rem .6rem;margin:.3rem 0;border:1px solid #2c3341;border-radius:.4rem;background:#1b1f27;cursor:pointer;font-size:.88rem}}
label.pick input{{margin-right:.4rem}}
.banner{{margin:.8rem 0;padding:.6rem .8rem;border-radius:.45rem;font-size:.9rem}}
.banner.ok{{background:#12301d;border:1px solid #235c37;color:#8fe0ab}}
.banner.no{{background:#2e1a1a;border:1px solid #5c2626;color:#f0a0a0}}
.banner.warn{{background:#2e2718;border:1px solid #5c4a26;color:#e0c07a}}
.fp{{font-family:ui-monospace,monospace;font-size:.72rem;color:#6f7789}}
details.dev{{margin:.35rem 0;border:1px solid #23262f;border-radius:.45rem;padding:.1rem .6rem}}
details.dev summary{{cursor:pointer;padding:.45rem 0;list-style:none}}
details.dev summary::-webkit-details-marker{{display:none}}
details.dev summary::before{{content:"▸ ";color:#6f7789}}
details.dev[open] summary::before{{content:"▾ "}}
.devbody{{padding:.2rem 0 .6rem .9rem;border-top:1px solid #1d2027}}
ul.grants{{list-style:none;padding:0;margin:.3rem 0}}
ul.grants li{{padding:.2rem 0;font-size:.85rem}}
.site{{font-family:ui-monospace,monospace;font-size:.75rem;background:#1b2330;border:1px solid #26313f;border-radius:.25rem;padding:.05rem .3rem}}
.tag.perm{{background:#2b2415;border:1px solid #63511f;color:#e2c26b}}
.tag.soon{{background:#1b2430;border:1px solid #2b3a4d;color:#8fb2d6}}
.tag.similar{{background:#2b2415;border:1px solid #5c4a26;color:#e0c07a;font-size:.62rem;text-transform:uppercase;letter-spacing:.04em}}
.note{{font-size:.74rem;color:#c9a86a;margin:.2rem 0 .1rem}}
.fp.full{{word-break:break-all;margin:.3rem 0}}
form.inline{{display:inline-flex;gap:.4rem;align-items:center;margin-left:.6rem}}
.confirm{{font-size:.72rem;color:#8b93a7}}
.vh{{position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden}}
.pname{{font-weight:600}} .puri{{color:#6f7789;font-size:.75rem;font-family:ui-monospace,monospace;word-break:break-all}}
.log{{border:1px solid #23262f;border-radius:.45rem;overflow:hidden;margin:.4rem 0}}
.logrow{{display:grid;grid-template-columns:9.5rem 5.5rem 1fr 1fr 7rem;gap:.6rem;align-items:center}}
.loghead{{background:#15181f;color:#8b93a7;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;padding:.4rem .6rem}}
details.logrow{{border-top:1px solid #1a1d24;font-size:.82rem}}
details.logrow summary{{cursor:pointer;padding:.4rem .6rem;list-style:none}}
details.logrow summary::-webkit-details-marker{{display:none}}
details.logrow summary:hover{{background:#151920}}
details.logrow[open] summary{{background:#171b23}}
.c-when{{font-family:ui-monospace,monospace;font-size:.74rem;color:#8b93a7;white-space:nowrap}}
.c-kind{{color:#a9b4c9}} .c-who{{color:#cfd6e4}} .c-item{{color:#cfd6e4}}
.c-out{{font-size:.74rem;text-align:right;white-space:nowrap}}
.logdetail{{padding:.5rem .8rem .7rem;background:#11141a;border-top:1px solid #1d2027}}
.kv{{display:grid;grid-template-columns:8rem 1fr;gap:.5rem;font-size:.76rem;padding:.12rem 0}}
.kv .k{{color:#6f7789;font-family:ui-monospace,monospace}}
.kv .v{{color:#cfd6e4;word-break:break-all}}
.pager{{display:flex;gap:.8rem;align-items:center;justify-content:center;font-size:.8rem;padding:.5rem 0}}
.pager a{{color:#8fb2d6;text-decoration:none}}
@media (max-width:640px){{
  .logrow{{grid-template-columns:1fr 1fr;grid-auto-rows:auto}}
  .c-out{{text-align:left}}
  .loghead{{display:none}}
}}
</style></head><body>
<h1>aac-broker · agent credential approvals</h1>
{flash}
{vault_block}
{pair_block}
<h2>Waiting for you ({n})</h2>
{pending_html}
<h2>Paired devices ({dn})</h2>
<ul>{devices_html}</ul>
<h2 id="activity">Recent activity</h2>
<div class="log">
  <div class="logrow loghead">
    <span>when</span><span>kind</span><span>who</span><span>item</span><span>outcome</span>
  </div>
  {audit_html}
</div>
{pager}
<script>
// The file stores epoch seconds. Render them in the viewer's own timezone
// instead of making the operator do UTC arithmetic.
// Copy buttons: clipboard API where allowed (this page is always HTTPS on the
// tailnet), else select the text so a long-press copy still works.
for (const btn of document.querySelectorAll('[data-copy]')) {{
  btn.addEventListener('click', async () => {{
    const text = btn.dataset.copy;
    const label = btn.querySelector('.copylabel');
    let ok = false;
    try {{
      await navigator.clipboard.writeText(text);
      ok = true;
    }} catch (e) {{
      const range = document.createRange();
      const target = document.getElementById('paircode');
      if (target) {{
        range.selectNodeContents(target);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }}
    }}
    if (label) {{
      label.textContent = ok ? 'copied' : 'select + copy';
      setTimeout(() => {{ label.textContent = 'copy'; }}, 1400);
    }}
  }});
}}

for (const el of document.querySelectorAll('[data-ts]')) {{
  const ts = Number(el.dataset.ts);
  if (!ts) continue;
  const d = new Date(ts * 1000);
  el.textContent = d.toLocaleString(undefined, {{
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  }});
  el.title = d.toISOString();
}}
</script>
</body></html>"#,
        n = pending.len(),
        flash = banner(msg),
        dn = device_count,
        audit_html = audit_html,
        pager = pager,
    )
}

#[derive(Deserialize)]
struct UnlockForm {
    password: String,
    ttl: u64,
}

async fn unlock(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<UnlockForm>,
) -> Response {
    if !st.authorised(&headers) {
        return denied("token required");
    }
    if !origin_ok(&headers, &st.expected_host) {
        return (StatusCode::FORBIDDEN, Html(String::from("bad origin"))).into_response();
    }
    if st.unlock_penalty_active() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html("<meta http-equiv=\"refresh\" content=\"30;url=/\"><p>Too many unlock attempts. Wait a few minutes.</p>".to_string()),
        )
            .into_response();
    }
    let ttl = f.ttl.clamp(600, 28_800);
    let _guard = st.unlock_lock.lock().await;
    match st.vault.unlock(&f.password).await {
        Ok(()) => {
            st.unlock_until.store(now() + ttl, Ordering::Relaxed);
            st.clear_unlock_failures();
            // Requests held while locked can now name their items. Resolve them
            // here so the redirect lands on cards the operator can act on,
            // instead of cards that need another round trip.
            let held = st.pending.awaiting_vault();
            let mut resolved = 0usize;
            for p in &held {
                let query = if p.by_id {
                    CredentialQuery::Id(p.requested.clone())
                } else {
                    CredentialQuery::Domain(p.requested.clone())
                };
                match crate::resolve_candidates(
                    &st.vault,
                    &query,
                    &p.requested,
                    st.collection.as_deref(),
                )
                .await
                {
                    Ok(items) if !items.is_empty() => {
                        if st.pending.fill(&p.id, items) {
                            resolved += 1;
                        }
                    }
                    Ok(_) => tracing::warn!(
                        "held request for {}: nothing in the vault matches that host",
                        p.requested
                    ),
                    Err(e) => tracing::warn!("held request for {}: {e}", p.requested),
                }
            }
            if !held.is_empty() {
                tracing::info!("resolved {resolved} of {} held request(s)", held.len());
            }
            if crate::vault::persist_enabled() {
                if let Err(e) = st.vault.save_session(&st.dir, now() + ttl) {
                    tracing::warn!("could not persist the vault session: {e}");
                }
            }
            let _ = st.audit.write(Entry {
                ts: now(),
                kind: "unlock",
                device: None,
                fingerprint: None,
                agent: None,
                requested: None,
                item_id: None,
                item_name: None,
                reason: None,
                outcome: "allowed",
                detail: Some(&format!(
                    "ttl={ttl}s, {resolved}/{} held request(s) resolved by {}",
                    held.len(),
                    st.actor(&headers)
                )),
            });
            see_other("unlocked")
        }
        Err(e) => {
            // The raw error goes to the journal only: `bw` stderr can carry
            // account detail, and it does not belong in the audit trail or a
            // push notification.
            tracing::warn!("unlock failed: {e}");
            let locked_out = st.note_unlock_failure();
            let _ = st.audit.write(Entry {
                ts: now(),
                kind: "unlock",
                device: None,
                fingerprint: None,
                agent: None,
                requested: None,
                item_id: None,
                item_name: None,
                reason: None,
                outcome: "denied",
                detail: Some(if locked_out {
                    "wrong password (now rate limited)"
                } else {
                    "wrong password"
                }),
            });
            if locked_out {
                if let Some(p) = &st.push {
                    p.notify(
                        "aac-broker: unlock locked out",
                        "Five failed unlock attempts; the page is refusing more for 10 minutes.",
                        None,
                    );
                }
            }
            (
                StatusCode::OK,
                Html("<p>Unlock failed.</p><p><a href=\"/\">back</a></p>".to_string()),
            )
                .into_response()
        }
    }
}

async fn lock(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !st.authorised(&headers) {
        return denied("token required");
    }
    if !origin_ok(&headers, &st.expected_host) {
        return (StatusCode::FORBIDDEN, Html(String::from("bad origin"))).into_response();
    }
    let _guard = st.unlock_lock.lock().await;
    st.unlock_until.store(0, Ordering::Relaxed);
    let _ = st.vault.lock().await;
    let _ = st.audit.write(Entry {
        ts: now(),
        kind: "lock",
        device: None,
        fingerprint: None,
        agent: None,
        requested: None,
        item_id: None,
        item_name: None,
        reason: None,
        outcome: "allowed",
        detail: Some(&format!("manual by {}", st.actor(&headers))),
    });
    st.vault.forget_session(&st.dir);
    see_other("locked")
}

#[derive(Deserialize)]
struct DecisionForm {
    id: String,
    choice: String,
    /// `0` / `900` / `3600` / `forever`.
    #[serde(default)]
    remember: String,
    /// Which candidate item the operator picked. Required for an approval.
    #[serde(default)]
    item: Option<String>,
}

async fn decision(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<DecisionForm>,
) -> Response {
    if !st.authorised(&headers) {
        return denied("token required");
    }
    if !origin_ok(&headers, &st.expected_host) {
        return (StatusCode::FORBIDDEN, Html(String::from("bad origin"))).into_response();
    }
    // Only the offered options, and only alongside an approval.
    let forever = f.remember == "forever";
    let remember: u64 = match f.remember.as_str() {
        "900" => 900,
        "3600" => 3600,
        _ => 0,
    };

    // An approval must name the item it approves, and that item must be one of
    // the candidates shown for this request. A denial names nothing.
    let choice = if f.choice == "approve" {
        let Some(snapshot) = st.pending.get(&f.id) else {
            return see_other("gone");
        };
        let Some(item_id) = f
            .item
            .as_deref()
            .filter(|id| snapshot.items.iter().any(|i| i.id == *id))
        else {
            return see_other("nopick");
        };
        if forever {
            Choice::ApprovePermanent {
                item_id: item_id.to_string(),
            }
        } else if remember > 0 {
            Choice::ApproveRemember {
                item_id: item_id.to_string(),
                secs: remember,
            }
        } else {
            Choice::Approve {
                item_id: item_id.to_string(),
            }
        }
    } else {
        Choice::Deny
    };

    // `resolve` hands back the record it removed: reading it from `get`
    // afterwards always returned None, which is why "remember" never stored.
    let Some(decided) = st.pending.resolve(&f.id, choice.clone()) else {
        return see_other("gone");
    };

    // A remembered or permanent approval is recorded against the exact vault
    // item, carrying the requested domain so the agent view reads as a site.
    let grant = match &choice {
        Choice::ApproveRemember { item_id, secs } => Some((item_id.clone(), *secs)),
        Choice::ApprovePermanent { item_id } => Some((item_id.clone(), 0)),
        _ => None,
    };
    if let Some((item_id, secs)) = grant {
        let name = decided
            .items
            .iter()
            .find(|i| i.id == item_id)
            .map(|i| i.name.clone())
            .unwrap_or_default();
        let domain = Some(decided.requested.as_str());
        // If the grant cannot be written, the approval must fail: the operator is about to be
        // told this site is remembered, and a grant that vanishes on the next start is worse than
        // no grant at all.
        let written = if secs == 0 {
            st.grants
                .add_permanent(&decided.fingerprint, &decided.device, &item_id, &name, domain)
        } else {
            st.grants
                .add(&decided.fingerprint, &decided.device, &item_id, &name, domain, secs)
        };
        if let Err(e) = written {
            let _ = st.audit.write(Entry {
                ts: now(),
                kind: "grant",
                device: Some(&decided.device),
                fingerprint: Some(&decided.fingerprint),
                agent: None,
                requested: Some(decided.requested.as_str()),
                item_id: Some(&item_id),
                item_name: Some(&name),
                reason: None,
                outcome: "grant-write-failed",
                detail: Some(&e),
            });
            return see_other("grant-failed");
        }
        let detail = if secs == 0 {
            format!("permanent by {}", st.actor(&headers))
        } else {
            format!("ttl={secs}s by {}", st.actor(&headers))
        };
        let _ = st.audit.write(Entry {
            ts: now(),
            kind: "grant",
            device: Some(&decided.device),
            fingerprint: Some(&decided.fingerprint),
            agent: decided.agent_claim.as_deref(),
            requested: Some(&decided.requested),
            item_id: Some(&item_id),
            item_name: Some(&name),
            reason: decided.reason.as_deref(),
            outcome: "remembered",
            detail: Some(&detail),
        });
    }
    match choice {
        Choice::Deny => see_other("denied"),
        Choice::ApprovePermanent { .. } => see_other("approved-forever"),
        _ => see_other("approved"),
    }
}

#[derive(Deserialize)]
struct RevokeForm {
    fingerprint: String,
    item_id: String,
}

#[derive(Deserialize)]
struct RevokeDeviceForm {
    fingerprint: String,
    confirm: Option<String>,
}

/// Unpair a device. The service loop owns the relay client, so the removal is
/// delegated to it: it stops the client, rewrites the store, then reconnects.
/// That ordering is the whole point — editing the file under a live client lets
/// the client write its in-memory copy back and silently undo the revocation.
async fn revoke_device(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<RevokeDeviceForm>,
) -> Response {
    if !st.authorised(&headers) {
        return denied("not authorised");
    }
    // Every other state-changing POST calls this; unpair used to skip it, and unpair is the most
    // destructive one on the page.
    if !origin_ok(&headers, &st.expected_host) {
        return (StatusCode::FORBIDDEN, Html(String::from("bad origin"))).into_response();
    }
    if f.confirm.as_deref() != Some("yes") {
        return see_other("unpair-failed");
    }

    let (tx, rx) = tokio::sync::oneshot::channel();
    if st
        .revoke_tx
        .send((f.fingerprint.clone(), tx))
        .await
        .is_err()
    {
        return see_other("unpair-failed");
    }

    let (outcome, detail) = match tokio::time::timeout(Duration::from_secs(15), rx).await {
        Ok(Ok(Ok(n))) if n > 0 => (
            "unpaired",
            format!("{} connection(s) removed", n),
        ),
        Ok(Ok(Ok(_))) => ("unpaired", "no matching device".to_string()),
        Ok(Ok(Err(e))) => ("unpair-failed", e),
        _ => ("unpair-failed", "service did not answer".to_string()),
    };

    let _ = st.audit.write(Entry {
        ts: now(),
        kind: "unpair",
        device: Some(&f.fingerprint),
        agent: None,
        requested: None,
        item_id: None,
        item_name: None,
        reason: None,
        outcome,
        fingerprint: Some(&f.fingerprint),
        detail: Some(&format!("{detail} by {}", st.actor(&headers))),
    });

    see_other(outcome)
}

async fn revoke(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<RevokeForm>,
) -> Response {
    if !st.authorised(&headers) {
        return denied("token required");
    }
    if !origin_ok(&headers, &st.expected_host) {
        return (StatusCode::FORBIDDEN, Html(String::from("bad origin"))).into_response();
    }
    let removed = match st.grants.revoke(&f.fingerprint, &f.item_id) {
        Ok(v) => v,
        Err(e) => {
            let _ = st.audit.write(Entry {
                ts: now(),
                kind: "grant",
                device: None,
                fingerprint: Some(&f.fingerprint),
                agent: None,
                requested: None,
                item_id: Some(&f.item_id),
                item_name: None,
                reason: None,
                outcome: "revoke-write-failed",
                detail: Some(&e),
            });
            return see_other("revoke-failed");
        }
    };
    let _ = st.audit.write(Entry {
        ts: now(),
        kind: "grant",
        device: None,
        fingerprint: Some(&f.fingerprint),
        agent: None,
        requested: None,
        item_id: Some(&f.item_id),
        item_name: None,
        reason: None,
        outcome: if removed { "revoked" } else { "absent" },
        detail: Some(&st.actor(&headers)),
    });
    see_other("revoked")
}

/// Withdraw an issued code. The relay owns the code itself and will not take it
/// back, but pairing only happens if this broker is *armed* for the next
/// fingerprint verification — so clearing the arming makes the code useless,
/// which is the part that matters.
fn cancel_pairing(st: &AppState) -> Option<String> {
    let armed = st
        .pair_arm
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take()
        .map(|(name, _)| name);
    let shown = st
        .pair_code
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take()
        .map(|(name, _, _)| name);
    armed.or(shown)
}

/// POST /pair/cancel — kill an outstanding pairing code.
async fn cancel_pair(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if !st.authorised(&headers) {
        return denied("not authorised");
    }
    if !origin_ok(&headers, &st.expected_host) {
        return (StatusCode::FORBIDDEN, Html(String::from("bad origin"))).into_response();
    }
    let Some(name) = cancel_pairing(&st) else {
        return see_other("pair-none");
    };
    let _ = st.audit.write(Entry {
        ts: now(),
        kind: "pairing",
        device: Some(&name),
        fingerprint: None,
        agent: None,
        requested: None,
        item_id: None,
        item_name: None,
        reason: None,
        outcome: "cancelled",
        detail: Some(&st.actor(&headers)),
    });
    see_other("pair-cancelled")
}

#[derive(Deserialize)]
struct PairForm {
    name: String,
}

async fn pair(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<PairForm>,
) -> Response {
    if !st.authorised(&headers) {
        return denied("token required");
    }
    if !origin_ok(&headers, &st.expected_host) {
        return (StatusCode::FORBIDDEN, Html(String::from("bad origin"))).into_response();
    }
    let Some(name) = clean_name(&f.name) else {
        return (StatusCode::BAD_REQUEST, Html(String::from("<p>Device name required.</p>"))).into_response();
    };
    // Ask the service loop for a code and WAIT for the relay's answer. Claiming
    // "code issued" before the code existed is what made the code vanish: the
    // redirect beat the relay, and the page had nothing to show.
    let (tx, rx) = tokio::sync::oneshot::channel();
    if st.pair_tx.send((name.clone(), tx)).await.is_err() {
        return see_other("pair-failed");
    }
    let (outcome, detail) = match tokio::time::timeout(Duration::from_secs(8), rx).await {
        Ok(Ok(Ok(_code))) => ("code issued", st.actor(&headers)),
        Ok(Ok(Err(e))) => ("code failed", format!("{e} by {}", st.actor(&headers))),
        _ => (
            "code timeout",
            format!("no answer from the relay by {}", st.actor(&headers)),
        ),
    };
    let _ = st.audit.write(Entry {
        ts: now(),
        kind: "pairing",
        device: Some(&name),
        fingerprint: None,
        agent: None,
        requested: None,
        item_id: None,
        item_name: None,
        reason: None,
        outcome,
        detail: Some(&detail),
    });
    if outcome == "code issued" {
        see_other("pair")
    } else {
        see_other("pair-failed")
    }
}

#[cfg(test)]
mod tests {
    // A poisoned mutex in a test is a failed test, not a production risk; the crate denies
    // unwrap in shipping code on purpose (see the clippy lint in Cargo.toml).
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::vault::Candidate;
    use crate::pending::PendingRequest;
    use axum::http::HeaderValue;

    /// Each call gets its own directory: tests run in parallel, and two threads
    /// writing the same `connections.tmp` meant one rename lost the file.
    fn st() -> Arc<AppState> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "aac-broker-web-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::create_dir_all(&dir);
        let (revoke_tx, _revoke_rx) = tokio::sync::mpsc::channel(1);
        Arc::new(AppState {
            dir: dir.clone(),
            collection: None,
            vault: Arc::new(Vault::new()),
            pending: Arc::new(Pending::default()),
            grants: Arc::new(Grants::load(&dir)),
            audit: Arc::new(Audit::load(&dir)),
            push: None,
            unlock_until: AtomicU64::new(0),
            expected_host: "broker.example".to_string(),
            unlock_lock: tokio::sync::Mutex::new(()),
            owner: "owner@example.com".to_string(),
            token: "s3cret-token-value".to_string(),
            allow_token: false,
            unlock_failures: std::sync::Mutex::new(Vec::new()),
            pair_tx: tokio::sync::mpsc::channel(1).0,
            pair_arm: std::sync::Mutex::new(None),
            pair_code: std::sync::Mutex::new(None),
            revoke_tx,
        })
    }

    #[test]
    fn the_unpair_form_carries_the_fingerprint_and_demands_confirmation() {
        let s = st();
        let mut conns = crate::storage::FileConnections::load(&s.dir).expect("load");
        conns
            .add_for_test("grokbot", [3u8; 32], 1_700_000_000)
            .expect("add");
        let html = render(&s, None, 1);
        let full = hex::encode([3u8; 32]);
        assert!(html.contains("Paired devices (1)"), "device count");
        assert!(
            html.contains(&format!("name=\"fingerprint\" value=\"{full}\"")),
            "unpair must name the exact device"
        );
        assert!(
            html.contains("name=\"confirm\" value=\"yes\" required"),
            "a bare tap must not revoke"
        );
    }

    #[test]
    fn a_permanent_approval_shows_under_its_own_device() {
        let s = st();
        let mut conns = crate::storage::FileConnections::load(&s.dir).expect("load");
        conns
            .add_for_test("hermes-lxc", [5u8; 32], 1_700_000_000)
            .expect("add");
        conns
            .add_for_test("grokbot", [6u8; 32], 1_700_000_100)
            .expect("add");
        let hermes_fp = hex::encode([5u8; 32]);
        let grok_fp = hex::encode([6u8; 32]);
        s.grants
            .add_permanent(&hermes_fp, "hermes-lxc", "item-github", "GitHub", Some("github.com"))
            .expect("grant");
        s.grants
            .add(&grok_fp, "grokbot", "item-stripe", "Stripe", Some("api.stripe.com"), 3600)
            .expect("grant");

        let html = render(&s, None, 1);
        assert!(html.contains("1 approval(s)"), "counts per device");

        // each device's approvals sit inside its own block, not a shared list
        let hermes_block = &html[html.find("<strong>hermes-lxc</strong>").expect("hermes")..];
        let grok_block = &html[html.find("<strong>grokbot</strong>").expect("grokbot")..];
        let hermes_upto_grok = &hermes_block[..hermes_block.len() - grok_block.len()];
        assert!(hermes_upto_grok.contains("github.com"), "site shown for hermes");
        assert!(hermes_upto_grok.contains("permanent"), "permanent badge");
        assert!(
            !hermes_upto_grok.contains("api.stripe.com"),
            "grokbot's approval must not appear under hermes"
        );
        assert!(grok_block.contains("api.stripe.com"));
        assert!(grok_block.contains("min left"), "timed approvals show remaining time");
    }

    fn write_entry(s: &AppState, ts: u64, item: &str, outcome: &str) {
        s.audit
            .write(Entry {
                ts,
                kind: "decision",
                device: Some("hermes-lxc"),
                fingerprint: Some("abcd1234"),
                agent: Some("hermes"),
                requested: Some("github.com"),
                item_id: Some("item-1"),
                item_name: Some(item),
                reason: Some("because"),
                outcome,
                detail: Some("ttl=3600s by owner@example.com"),
            })
            .expect("audit write");
    }

    #[test]
    fn activity_log_shows_time_not_epoch_pages_newest_first_and_drills_down() {
        let s = st();
        for i in 0..30u64 {
            write_entry(&s, 1_700_000_000 + i, &format!("entry-{i}"), "allowed");
        }

        let p1 = render(&s, None, 1);
        assert!(p1.contains("2023-11-14"), "a date-time must be displayed");
        assert!(
            !p1.contains(">1700000029<"),
            "the raw epoch must not be the cell text"
        );
        // newest on top of page 1, and 25 per page
        let newest = p1.find("entry-29").expect("newest entry present");
        let oldest_on_page = p1.find("entry-5").expect("25th newest present");
        assert!(newest < oldest_on_page, "newest must come first");
        assert!(!p1.contains("entry-4"), "page 1 must stop at 25 entries");
        assert!(p1.contains("page 1 of 2"), "pager count");
        assert!(p1.contains("?page=2#activity"), "link to older page");

        // the drill-down carries the whole record, not just the columns
        assert!(p1.contains("class=\"logdetail\""));
        assert!(p1.contains("ttl=3600s by owner@example.com"));

        let p2 = render(&s, None, 2);
        assert!(p2.contains("entry-4") && p2.contains("entry-0"));
        assert!(!p2.contains("entry-29"), "page 2 is older, not newer");
        assert!(p2.contains("?page=1#activity"));
    }

    #[test]
    fn the_pairing_code_has_a_copy_control_carrying_that_code() {
        let s = st();
        *s.pair_code.lock().unwrap() = Some((
            "grokbot".to_string(),
            "ABC-DEF-GHI".to_string(),
            Instant::now(),
        ));
        let html = render(&s, None, 1);
        assert!(html.contains("ABC-DEF-GHI"), "code shown");
        assert!(
            html.contains(r#"data-copy="ABC-DEF-GHI""#),
            "the button must carry the exact code to copy"
        );
        assert!(html.contains("class=\"copylabel\""), "visible feedback label");
        assert!(html.contains("navigator.clipboard"), "clipboard handler present");
    }

    #[test]
    fn cancelling_clears_the_code_and_the_arming_so_it_cannot_pair() {
        let s = st();
        *s.pair_code.lock().unwrap() = Some((
            "grokbot".to_string(),
            "ABC-DEF-GHI".to_string(),
            Instant::now(),
        ));
        *s.pair_arm.lock().unwrap() = Some(("grokbot".to_string(), Instant::now()));

        // the cancel button is offered while a code is live
        assert!(render(&s, None, 1).contains("/pair/cancel"));

        assert_eq!(cancel_pairing(&s), Some("grokbot".to_string()));
        assert!(
            s.pair_arm.lock().unwrap().is_none(),
            "pre-existing arming must be cleared: it is what authorises pairing"
        );
        assert!(s.pair_code.lock().unwrap().is_none());
        // the panel falls back to offering a fresh code, and cancelling again is a no-op
        assert!(!render(&s, None, 1).contains("/pair/cancel"));
        assert_eq!(cancel_pairing(&s), None);
    }

    #[test]
    fn a_request_held_while_locked_offers_unlock_and_not_an_approval() {
        let s = st();
        let _rx = s.pending.open(PendingRequest {
            locked: true,
            by_id: false,
            id: "held-1".to_string(),
            device: "hermes-lxc".to_string(),
            fingerprint: "abcdef0123456789".to_string(),
            agent_claim: Some("hermes".to_string()),
            reason: Some("check gh auth".to_string()),
            requested: "github.com".to_string(),
            items: Vec::new(),
            created: Instant::now(),
        });
        let html = render(&s, None, 1);
        assert!(html.contains("asked for <code>github.com</code>"), "the ask is shown");
        assert!(html.contains("Vault is locked"), "state is explained");
        assert!(html.contains("action=\"/unlock\""), "unlock is offered here");
        assert!(html.contains("value=\"deny\""), "you can still refuse");
        assert!(
            !html.contains("value=\"approve\""),
            "nothing may be approved while the item is unknown"
        );

        // once the vault opens and the candidates are filled, it becomes a normal card
        s.pending.fill(
            "held-1",
            vec![Candidate {
                id: "item-1".to_string(),
                name: "GitHub".to_string(),
                username: Some("agent@example.com".to_string()),
                uris: vec!["https://github.com".to_string()],
            }],
        );
        let after = render(&s, None, 1);
        assert!(after.contains("value=\"approve\""), "approval is available now");
        assert!(after.contains("GitHub"), "the item is named now");
        assert!(!after.contains("Vault is locked — unlock to see which login"));
    }

    #[test]
    fn a_different_host_is_offered_and_marked_similar() {
        let s = st();
        let _rx = s.pending.open(PendingRequest {
            locked: false,
            by_id: false,
            id: "fuzzy-1".to_string(),
            device: "grokbot".to_string(),
            fingerprint: "abcdef0123456789".to_string(),
            agent_claim: Some("grokbot".to_string()),
            reason: Some("connection test".to_string()),
            requested: "racv.com.au".to_string(),
            items: vec![Candidate {
                id: "item-racv".to_string(),
                name: "RACV".to_string(),
                username: None,
                uris: vec!["https://www.racv.com.au".to_string()],
            }],
            created: Instant::now(),
        });
        let html = render(&s, None, 1);
        assert!(html.contains("www.racv.com.au"), "the item's real URI is shown");
        assert!(
            html.contains("no exact host match for <code>racv.com.au</code>"),
            "the mismatch is stated, not hidden"
        );
        assert!(html.contains("type=\"hidden\" name=\"item\" value=\"item-racv\""));

        // a host that does match carries no warning
        s.pending.expire("fuzzy-1");
        let _rx = s.pending.open(PendingRequest {
            locked: false,
            by_id: false,
            id: "exact-1".to_string(),
            device: "grokbot".to_string(),
            fingerprint: "abcdef0123456789".to_string(),
            agent_claim: None,
            reason: None,
            requested: "racv.com.au".to_string(),
            items: vec![Candidate {
                id: "item-racv".to_string(),
                name: "RACV".to_string(),
                username: None,
                uris: vec!["https://racv.com.au".to_string()],
            }],
            created: Instant::now(),
        });
        assert!(!render(&s, None, 1).contains("no exact host match"));
    }

    #[test]
    fn every_unlock_form_is_ready_for_phone_autofill() {
        let s = st();
        // locked page (vault panel form)
        let locked = render(&s, None, 1);
        let forms: Vec<&str> = locked.match_indices("action=\"/unlock\"").map(|(i, _)| &locked[i..]).collect();
        assert!(!forms.is_empty(), "there must be an unlock form");
        for f in &forms {
            let f = &f[..f.find("</form>").unwrap_or(f.len())];
            assert!(f.contains("autocomplete=\"current-password\""), "password autofill hint");
            assert!(f.contains("autocomplete=\"username\""), "username anchor for the manager");
            assert!(f.contains("autocapitalize=\"off\""), "no autocapitalise on iOS");
            assert!(f.contains("enterkeyhint=\"go\""), "keyboard says go");
            assert!(!f.contains("{owner}"), "the owner must be substituted, not left as a placeholder");
        }
        // and the same on a card that asks you to unlock mid-request
        let s2 = st();
        let _rx = s2.pending.open(PendingRequest {
            locked: true,
            by_id: false,
            id: "held".to_string(),
            device: "hermes-lxc".to_string(),
            fingerprint: "abcdef0123456789".to_string(),
            agent_claim: None,
            reason: None,
            requested: "github.com".to_string(),
            items: Vec::new(),
            created: Instant::now(),
        });
        let card = render(&s2, None, 1);
        let i = card.find("action=\"/unlock\"").expect("card unlock form");
        let form = &card[i..i + card[i..].find("</form>").expect("end")];
        assert!(form.contains("autocomplete=\"current-password\""));
        assert!(form.contains("owner@example.com"), "owner filled in");
    }

    #[test]
    fn every_unlock_form_offers_one_two_four_and_eight_hours_defaulting_to_two() {
        // Both surfaces, same four choices, same default: what the operator sees
        // must not depend on where they unlock from.
        let check = |html: &str, label: &str| {
            let i = html.find("name=\"ttl\"").unwrap_or_else(|| panic!("{label}: ttl select"));
            let block = &html[i..i + html[i..].find("</select>").expect("end select")];
            for hours in [1u64, 2, 4, 8] {
                // the selected option carries an attribute after the value, so
                // match the value alone
                assert!(
                    block.contains(&format!("value=\"{}\"", hours * 3600)),
                    "{label}: {hours}h option missing"
                );
            }
            assert!(
                block.contains("value=\"7200\" selected"),
                "{label}: 2h must be the default"
            );
        };

        let s = st();
        // surface 1: the vault panel, when locked
        check(&render(&s, None, 1), "vault panel");

        // surface 2: the inline form on a request card that arrived while locked
        let s2 = st();
        let _rx = s2.pending.open(PendingRequest {
            locked: true,
            by_id: false,
            id: "held".to_string(),
            device: "hermes-lxc".to_string(),
            fingerprint: "abcdef0123456789".to_string(),
            agent_claim: None,
            reason: None,
            requested: "github.com".to_string(),
            items: Vec::new(),
            created: Instant::now(),
        });
        check(&render(&s2, None, 1), "locked request card");
    }

    #[test]
    fn escaping_kills_markup_from_agent_supplied_strings() {
        assert_eq!(esc("<script>x</script>"), "&lt;script&gt;x&lt;/script&gt;");
        assert_eq!(esc("a\"b'c&d"), "a&quot;b&#39;c&amp;d");
        assert_eq!(esc("bad\u{7}bell"), "badbell");
    }

    #[test]
    fn same_origin_check_allows_absent_origin_and_matching_host() {
        let mut h = HeaderMap::new();
        assert!(origin_ok(&h, "broker.example"));
        h.insert("origin", HeaderValue::from_static("https://broker.example"));
        assert!(origin_ok(&h, "broker.example"));
        h.insert("origin", HeaderValue::from_static("https://evil.example"));
        assert!(!origin_ok(&h, "broker.example"));
    }

    #[test]
    fn constant_time_compare_matches_only_equal_bytes() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"a"));
    }

    fn served_headers(login: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("tailscale-user-login", HeaderValue::from_static(login));
        h.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
        h
    }

    #[test]
    fn the_owner_identity_from_serve_is_accepted() {
        let s = st();
        assert!(s.authorised(&served_headers("owner@example.com")));
        // Tailscale logins are case-insensitive.
        assert!(s.authorised(&served_headers("OWNER@EXAMPLE.COM")));
    }

    #[test]
    fn another_tailnet_user_is_refused() {
        let s = st();
        assert!(!s.authorised(&served_headers("someone@else.example")));
    }

    #[test]
    fn a_header_without_serve_forwarding_is_refused() {
        // A local process could set the header itself; Serve always adds
        // X-Forwarded-For, so requiring it rejects the naive forgery.
        let s = st();
        let mut h = HeaderMap::new();
        h.insert(
            "tailscale-user-login",
            HeaderValue::from_static("owner@example.com"),
        );
        assert!(!s.authorised(&h));
    }

    #[test]
    fn tagged_devices_cannot_approve_because_serve_sends_no_identity() {
        let s = st();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
        assert!(!s.authorised(&h));
    }

    #[test]
    fn the_token_is_dead_unless_break_glass_is_enabled() {
        let s = st();
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer s3cret-token-value"),
        );
        assert!(!s.authorised(&h), "token path must be off by default");
        let mut a = st();
        Arc::get_mut(&mut a).expect("sole owner").allow_token = true;
        assert!(a.authorised(&h));
        let mut c = HeaderMap::new();
        c.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; aac=s3cret-token-value"),
        );
        assert!(a.authorised(&c));
    }

    #[test]
    fn actor_is_reported_for_the_audit_line() {
        let s = st();
        assert_eq!(s.actor(&served_headers("owner@example.com")), "owner@example.com");
        assert_eq!(s.actor(&HeaderMap::new()), "break-glass token");
    }

    fn decision_form(html: &str) -> &str {
        let start = html.find("action=\"/decision\"").expect("decision form");
        let end = html[start..].find("</form>").expect("form end") + start;
        &html[start..end]
    }

    #[tokio::test]
    async fn the_item_control_is_inside_the_decision_form() {
        // Regression: the item field used to render before <form>, so Approve
        // submitted no item and the page answered "pick which item first".
        let s = st();
        let _rx = s.pending.open(PendingRequest {
            locked: false,
            by_id: false,
            id: "req-1".to_string(),
            device: "hermes-lxc".to_string(),
            fingerprint: "abcdef0123456789".to_string(),
            agent_claim: Some("hermes".to_string()),
            reason: Some("check gh auth".to_string()),
            requested: "github.com".to_string(),
            items: vec![Candidate {
                id: "item-single".to_string(),
                name: "GitHub".to_string(),
                username: Some("agent@example.com".to_string()),
                uris: vec!["https://github.com".to_string()],
            }],
            created: Instant::now(),
        });
        let html = render(&s, None, 1);
        let form = decision_form(&html);
        assert!(
            form.contains("name=\"item\" value=\"item-single\""),
            "single-item card must submit its item id: {form}"
        );
        assert!(
            form.contains("value=\"forever\""),
            "the card must offer a permanent approval"
        );
    }

    #[tokio::test]
    async fn several_matches_render_radios_inside_the_form() {
        let s = st();
        let mk = |id: &str, name: &str| Candidate {
            id: id.to_string(),
            name: name.to_string(),
            username: None,
            uris: vec!["https://github.com".to_string()],
        };
        let _rx = s.pending.open(PendingRequest {
            locked: false,
            by_id: false,
            id: "req-2".to_string(),
            device: "hermes-lxc".to_string(),
            fingerprint: "abcdef0123456789".to_string(),
            agent_claim: None,
            reason: None,
            requested: "github.com".to_string(),
            items: vec![mk("item-a", "GitHub work"), mk("item-b", "GitHub personal")],
            created: Instant::now(),
        });
        let html = render(&s, None, 1);
        let form = decision_form(&html);
        assert!(form.contains("type=\"radio\" name=\"item\" value=\"item-a\""));
        assert!(form.contains("type=\"radio\" name=\"item\" value=\"item-b\""));
        assert!(form.contains("GitHub personal"), "candidates must be labelled");
    }

    #[test]
    fn unlock_lockout_arms_after_five_failures() {
        let s = st();
        for _ in 0..4 {
            assert!(!s.note_unlock_failure());
        }
        assert!(s.note_unlock_failure());
        assert!(s.unlock_penalty_active());
        s.clear_unlock_failures();
        assert!(!s.unlock_penalty_active());
    }
}
