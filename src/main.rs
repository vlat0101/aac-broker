//! aac-broker — Bitwarden Agent Access approval broker.
//!
//! Replaces `aac listen`'s terminal UI with a background `UserClient` plus an
//! approval page published on the tailnet. Credential requests arrive as
//! protocol messages, are resolved against the vault, and are released only
//! after an explicit decision — or from a remembered `(device, item)` grant that
//! the operator created by approving one specific request.

mod audit;
mod pending;
mod policy;
mod push;
mod storage;
mod vault;
mod web;

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ap_client::{
    AuditEvent, AuditLog, CredentialData, CredentialQuery, CredentialRequestReply,
    DefaultProxyClient, FingerprintVerificationReply, UserClient, UserClientHandle,
    UserClientNotification, UserClientRequest,
};
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use tokio::sync::Semaphore;
use tracing::{info, warn};
use zeroize::Zeroizing;

use audit::{Audit, Entry};
use pending::{Choice, Decision, Pending, PendingRequest};
use policy::Grants;
use push::Pushover;
use storage::{short_hex, FileConnections, FileIdentity};
use vault::{Candidate, Vault};

const PAIR_WINDOW: Duration = Duration::from_secs(300);
const DEFAULT_PROXY: &str = "wss://ap.lesspassword.dev";
const DEFAULT_LISTEN: &str = "127.0.0.1:8787";
/// Requests handled at once. Anything beyond this is denied rather than queued:
/// a request nobody is looking at is not worth holding open.
const MAX_IN_FLIGHT: usize = 4;
/// How much of an agent's requested string is even considered.
const MAX_QUERY: usize = 200;

#[derive(Parser)]
#[command(name = "aac-broker", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the broker: relay listener plus the approval page.
    Serve {
        #[arg(long, default_value = DEFAULT_PROXY)]
        proxy_url: String,
        /// Issue a one-time pairing code for this device name at startup.
        #[arg(long)]
        pair: Option<String>,
    },
    /// Report what the Bitwarden CLI thinks its state is (ops diagnostic).
    VaultStatus,
    /// List remembered approvals.
    Grants,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct AuditSink;

#[async_trait]
impl AuditLog for AuditSink {
    async fn write(&self, event: AuditEvent<'_>) {
        match event {
            AuditEvent::ConnectionEstablished {
                remote_identity,
                remote_name,
                ..
            } => info!(
                "audit: connected {} ({})",
                remote_name.unwrap_or("unnamed"),
                short_hex(remote_identity)
            ),
            AuditEvent::ConnectionRejected { remote_identity } => {
                info!("audit: rejected {}", short_hex(remote_identity))
            }
            other => info!("audit: event {other:?}"),
        }
    }
}

type BoxError = Box<dyn std::error::Error>;

fn query_label(q: &CredentialQuery) -> String {
    match q {
        CredentialQuery::Domain(d) => d.clone(),
        CredentialQuery::Id(id) => format!("item {id}"),
        CredentialQuery::Search(s) => format!("search \"{s}\""),
    }
}

/// `item | agent | reason` — the agent's own claims, stripped before lookup.
struct Ask {
    what: String,
    agent: Option<String>,
    reason: Option<String>,
}

fn clean(s: &str, max: usize) -> Option<String> {
    let out: String = s
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect();
    let out = out.split_whitespace().collect::<Vec<_>>().join(" ");
    (!out.is_empty()).then_some(out)
}

fn parse_ask(raw: &str) -> Ask {
    let capped: String = raw.chars().take(MAX_QUERY).collect();
    let mut parts = capped.split('|').map(str::trim);
    let what = parts.next().unwrap_or_default().to_string();
    let second = parts.next().and_then(|s| clean(s, 40));
    let third = parts.next().and_then(|s| clean(s, 120));
    // "item | reason" is a legal two-part form: then there is no agent claim.
    match (second, third) {
        (Some(a), Some(r)) => Ask {
            what,
            agent: Some(a),
            reason: Some(r),
        },
        (Some(r), None) => Ask {
            what,
            agent: None,
            reason: Some(r),
        },
        _ => Ask {
            what,
            agent: None,
            reason: None,
        },
    }
}

/// Normalise a URI or bare domain to a comparable host: lowercase, no scheme,
/// no userinfo, no port, no path, no trailing dot.
pub(crate) fn host_of(uri: &str) -> String {
    let lowered = uri.trim().to_lowercase();
    let s = lowered
        .strip_prefix("https://")
        .or_else(|| lowered.strip_prefix("http://"))
        .or_else(|| lowered.strip_prefix("androidapp://"))
        .unwrap_or(lowered.as_str());
    let s = s.split(['/', '?', '#']).next().unwrap_or_default();
    let s = s.rsplit('@').next().unwrap_or(s); // drop user:pass@
    let s = match s.rsplit_once(':') {
        Some((head, port)) if port.chars().all(|c| c.is_ascii_digit()) => head,
        _ => s,
    };
    s.trim_end_matches('.').to_string()
}

/// Every item whose normalised host equals the requested host.
///
/// No "first match wins", no suffix matching, no accepting a lone fuzzy search
/// hit: those all release a credential the agent did not name. Zero matches
/// denies; several matches is *not* an error — the operator picks one on the
/// page, because only a human can tell two logins for the same host apart.
/// `bw list items --search` is a substring search, so this filter is what makes
/// the candidate set meaningful.
/// Resolve a request to candidate items. One definition, used by the service
/// when a request arrives and by the page when a request that arrived locked is
/// resolved at unlock time — the two must not drift, or the page would offer an
/// item the service would not release.
pub(crate) async fn resolve_candidates(
    vault: &Vault,
    query: &CredentialQuery,
    what: &str,
    collection: Option<&str>,
) -> Result<Vec<Candidate>, String> {
    match query {
        CredentialQuery::Id(id) => vault.candidate_by_id(id).await.map(|c| vec![c]),
        _ => {
            let mut hits = vault.candidates(what, collection).await?;
            // A narrow term can miss an item stored under a wider host, e.g.
            // "www.racv.com.au" against an item whose URI is "racv.com.au".
            if hits.is_empty() {
                let base = registrable(&host_of(what));
                if !base.is_empty() && base != what {
                    hits = vault.candidates(&base, collection).await?;
                }
            }
            Ok(rank_candidates(&hits, what))
        }
    }
}

/// Most items to offer on one card. Beyond this the picker stops being a
/// decision and becomes a list you scroll.
pub(crate) const MAX_CANDIDATES: usize = 12;

/// Order the vault's search hits for a request. Items are **not** dropped for
/// having a different host: the operator decides which login is right, and a
/// vault that stores `www.racv.com.au` should still answer a request for
/// `racv.com.au`. Host similarity only affects the order.
pub(crate) fn rank_candidates(candidates: &[Candidate], domain: &str) -> Vec<Candidate> {
    let wanted = host_of(domain);
    if wanted.is_empty() {
        return candidates.iter().take(MAX_CANDIDATES).cloned().collect();
    }
    let base = registrable(&wanted);
    let mut scored: Vec<(u8, usize, Candidate)> = candidates
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let score = c
                .uris
                .iter()
                .map(|u| host_score(&host_of(u), &wanted, &base))
                .max()
                .unwrap_or(0);
            (score, i, c.clone())
        })
        .collect();
    // Best host match first; otherwise keep the vault's own order.
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored
        .into_iter()
        .take(MAX_CANDIDATES)
        .map(|(_, _, c)| c)
        .collect()
}

/// 3 exact host, 2 sub/super-domain, 1 same registrable domain, 0 unrelated.
fn host_score(host: &str, wanted: &str, base: &str) -> u8 {
    if host == wanted {
        return 3;
    }
    // A bare TLD ("com") is not a host: without this, every .com item would look
    // like a superdomain match for a request of "com".
    if !wanted.contains('.') || !host.contains('.') {
        return 0;
    }
    if host.ends_with(&format!(".{wanted}")) || wanted.ends_with(&format!(".{host}")) {
        2
    } else if !base.is_empty() && (host == base || host.ends_with(&format!(".{base}"))) {
        1
    } else {
        0
    }
}

/// Last two labels: `www.racv.com.au` -> `racv.com.au`.
pub(crate) fn registrable(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() <= 2 {
        parts.join(".")
    } else {
        parts[parts.len() - 2..].join(".")
    }
}

struct Service {
    st: Arc<web::AppState>,
    dir: PathBuf,
    collection: Option<String>,
    approval_timeout: Duration,
    sem: Arc<Semaphore>,
}

impl Service {
    fn deny(
        &self,
        device: &str,
        fingerprint: &str,
        ask: &Ask,
        reply: tokio::sync::oneshot::Sender<CredentialRequestReply>,
        outcome: &str,
        why: &str,
    ) {
        info!("deny ({outcome}): {why}");
        let _ = self.st.audit.write(Entry {
            ts: now(),
            kind: "decision",
            device: Some(device),
            fingerprint: Some(fingerprint),
            agent: ask.agent.as_deref(),
            requested: Some(&ask.what),
            item_id: None,
            item_name: None,
            reason: ask.reason.as_deref(),
            outcome,
            detail: Some(why),
        });
        let _ = reply.send(CredentialRequestReply {
            approved: false,
            credential: None,
            credential_id: None,
        });
    }

    async fn handle(
        &self,
        query: CredentialQuery,
        identity: ap_proxy_protocol::IdentityFingerprint,
        reply: tokio::sync::oneshot::Sender<CredentialRequestReply>,
    ) {
        let started = Instant::now();
        let fingerprint = hex::encode(identity.0);
        let device = FileConnections::load(&self.dir)
            .ok()
            .and_then(|c| c.label(&identity))
            .unwrap_or_else(|| short_hex(&identity));
        let ask = parse_ask(&query_label(&query));

        let _ = self.st.audit.write(Entry {
            ts: now(),
            kind: "request",
            device: Some(&device),
            fingerprint: Some(&fingerprint),
            agent: ask.agent.as_deref(),
            requested: Some(&ask.what),
            item_id: None,
            item_name: None,
            reason: ask.reason.as_deref(),
            outcome: "pending",
            detail: None,
        });

        // A locked vault cannot resolve an item, but that is not a reason to bin
        // the request: hold it so the operator can unlock from the card. Only the
        // release needs a live session, and that is checked again there.
        let unlocked = self.st.unlocked();

        // Resolve the request to the candidate items. An id request is fetched
        // by id; a domain request yields *every* item whose host matches.
        let mut items: Vec<Candidate> = Vec::new();
        if unlocked {
            items = match resolve_candidates(
                &self.st.vault,
                &query,
                &ask.what,
                self.collection.as_deref(),
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    warn!("vault lookup failed: {e}");
                    return self.deny(
                        &device,
                        &fingerprint,
                        &ask,
                        reply,
                        "error",
                        "vault lookup failed",
                    );
                }
            };
        }

        if unlocked && items.is_empty() {
            return self.deny(
                &device,
                &fingerprint,
                &ask,
                reply,
                "denied",
                "nothing in the vault matched that host",
            );
        }

        // A remembered approval is for one specific item. If exactly one of the
        // candidates is remembered, release that one without prompting; if two
        // are, the operator has to choose again rather than have us guess.
        let remembered: Vec<&Candidate> = items
            .iter()
            .filter(|i| self.st.grants.is_granted(&fingerprint, &i.id))
            .collect();
        if remembered.len() == 1 {
            let item = remembered[0];
            let _ = self.st.audit.write(Entry {
                ts: now(),
                kind: "decision",
                device: Some(&device),
                fingerprint: Some(&fingerprint),
                agent: ask.agent.as_deref(),
                requested: Some(&ask.what),
                item_id: Some(&item.id),
                item_name: Some(&item.name),
                reason: ask.reason.as_deref(),
                outcome: "remembered",
                detail: None,
            });
            return self.release(reply, item, &ask, &device, &fingerprint).await;
        }

        let id = format!("{}-{}", now(), short_hex(&identity));
        let rx = self.st.pending.open(PendingRequest {
            locked: !unlocked,
            by_id: matches!(query, CredentialQuery::Id(_)),
            id: id.clone(),
            device: device.clone(),
            fingerprint: fingerprint.clone(),
            agent_claim: ask.agent.clone(),
            reason: ask.reason.clone(),
            requested: ask.what.clone(),
            items: items.clone(),
            created: Instant::now(),
        });
        if let Some(push) = &self.st.push {
            let what = if !unlocked {
                format!("access to {} (vault locked)", ask.what)
            } else if items.len() == 1 {
                format!("your {} password", items[0].name)
            } else {
                format!("one of {} matches for {}", items.len(), ask.what)
            };
            push.notify(
                &format!(
                    "{} wants {what}",
                    ask.agent.as_deref().unwrap_or(&device)
                ),
                &format!(
                    "{} · {}{}",
                    device,
                    what,
                    items
                        .first()
                        .and_then(|i| i.username.as_deref())
                        .map(|u| format!(" ({u})"))
                        .unwrap_or_default()
                ),
                std::env::var("AAC_BROKER_PUBLIC_URL").ok().as_deref(),
            );
        }

        match tokio::time::timeout(self.approval_timeout, rx).await {
            Ok(Ok(Decision {
                choice: Choice::Approve { item_id },
                items,
            }))
            | Ok(Ok(Decision {
                choice: Choice::ApproveRemember { item_id, .. },
                items,
            }))
            | Ok(Ok(Decision {
                choice: Choice::ApprovePermanent { item_id },
                items,
            })) => {
                let Some(item) = items.iter().find(|i| i.id == item_id) else {
                    return self.deny(
                        &device,
                        &fingerprint,
                        &ask,
                        reply,
                        "error",
                        "approved item was not among the candidates",
                    );
                };
                let _ = self.st.audit.write(Entry {
                    ts: now(),
                    kind: "decision",
                    device: Some(&device),
                    fingerprint: Some(&fingerprint),
                    agent: ask.agent.as_deref(),
                    requested: Some(&ask.what),
                    item_id: Some(&item.id),
                    item_name: Some(&item.name),
                    reason: ask.reason.as_deref(),
                    outcome: "allowed",
                    detail: Some(&format!(
                        "{}ms, {} candidate(s)",
                        started.elapsed().as_millis(),
                        items.len()
                    )),
                });
                self.release(reply, item, &ask, &device, &fingerprint).await;
            }
            Ok(Ok(Decision {
                choice: Choice::Deny,
                items,
            })) => {
                let _ = self.st.audit.write(Entry {
                    ts: now(),
                    kind: "decision",
                    device: Some(&device),
                    fingerprint: Some(&fingerprint),
                    agent: ask.agent.as_deref(),
                    requested: Some(&ask.what),
                    item_id: None,
                    item_name: None,
                    reason: ask.reason.as_deref(),
                    outcome: "denied",
                    detail: Some(&format!("operator, {} candidate(s)", items.len())),
                });
                let _ = reply.send(CredentialRequestReply {
                    approved: false,
                    credential: None,
                    credential_id: None,
                });
            }
            _ => {
                self.st.pending.expire(&id);
                let _ = self.st.audit.write(Entry {
                    ts: now(),
                    kind: "decision",
                    device: Some(&device),
                    fingerprint: Some(&fingerprint),
                    agent: ask.agent.as_deref(),
                    requested: Some(&ask.what),
                    item_id: None,
                    item_name: None,
                    reason: ask.reason.as_deref(),
                    outcome: "timeout",
                    detail: Some(if unlocked {
                        "no decision before the window closed"
                    } else {
                        "no decision; the vault was locked for the whole window"
                    }),
                });
                let _ = reply.send(CredentialRequestReply {
                    approved: false,
                    credential: None,
                    credential_id: None,
                });
            }
        }
    }


    /// Fetch the secret and hand it over. The delivery is audited *after* a
    /// successful send, so the trail can distinguish "approved" from
    /// "actually received", and an unauditable authorisation is refused.
    async fn release(
        &self,
        reply: tokio::sync::oneshot::Sender<CredentialRequestReply>,
        item: &Candidate,
        ask: &Ask,
        device: &str,
        fingerprint: &str,
    ) {
        let credential = match self.st.vault.credential(&item.id).await {
            Ok(c) => c,
            Err(e) => {
                warn!("vault read failed: {e}");
                let _ = self.st.audit.write(Entry {
                    ts: now(),
                    kind: "decision",
                    device: Some(device),
                    fingerprint: Some(fingerprint),
                    agent: ask.agent.as_deref(),
                    requested: Some(&ask.what),
                    item_id: Some(&item.id),
                    item_name: Some(&item.name),
                    reason: ask.reason.as_deref(),
                    outcome: "error",
                    detail: Some("vault read failed"),
                });
                let _ = reply.send(CredentialRequestReply {
                    approved: false,
                    credential: None,
                    credential_id: None,
                });
                return;
            }
        };

        let credential_id = credential.item_id.clone();
        let sent = reply.send(CredentialRequestReply {
            approved: true,
            credential: Some(CredentialData {
                username: credential.username,
                password: credential.password.map(Zeroizing::new),
                totp: credential.totp,
                uri: credential.uri,
                // Never released: notes can hold recovery codes.
                notes: None,
                credential_id: Some(credential_id.clone()),
                domain: Some(ask.what.clone()),
            }),
            credential_id: Some(credential_id),
        });

        if sent.is_err() {
            // The requester went away between approval and delivery.
            let _ = self.st.audit.write(Entry {
                ts: now(),
                kind: "decision",
                device: Some(device),
                fingerprint: Some(fingerprint),
                agent: ask.agent.as_deref(),
                requested: Some(&ask.what),
                item_id: Some(&item.id),
                item_name: Some(&item.name),
                reason: ask.reason.as_deref(),
                outcome: "undelivered",
                detail: Some("requester closed the channel"),
            });
            return;
        }
        if let Err(e) = self.st.audit.write(Entry {
            ts: now(),
            kind: "decision",
            device: Some(device),
            fingerprint: Some(fingerprint),
            agent: ask.agent.as_deref(),
            requested: Some(&ask.what),
            item_id: Some(&item.id),
            item_name: Some(&item.name),
            reason: ask.reason.as_deref(),
            outcome: "released",
            detail: None,
        }) {
            // Cannot undo the send; make the failure loud instead of silent.
            tracing::error!("AUDIT WRITE FAILED after release: {e}");
            if let Some(p) = &self.st.push {
                p.notify(
                    "aac-broker: audit write failed",
                    &format!("A credential was released but not recorded: {e}"),
                    None,
                );
            }
        }
    }
}

async fn connect(dir: &Path, proxy_url: &str) -> Result<UserClientHandle, ap_client::ClientError> {
    let identity = Box::new(FileIdentity::load_or_generate(dir)?);
    let connections = Box::new(FileConnections::load(dir)?);
    let proxy = Box::new(DefaultProxyClient::from_url(proxy_url.to_string()));
    UserClient::connect(identity, connections, proxy, Some(Box::new(AuditSink)), None).await
}

/// Ask the relay for a one-time pairing code and arm the next fingerprint
/// verification. Called at startup (`--pair`) and from the page's pair form, so
/// adding an agent host never requires restarting the service — which would
/// throw away the unlocked vault session. The code itself is never logged: it
/// is shown on the page and nowhere else.
async fn issue_code(
    client: &UserClient,
    st: &Arc<web::AppState>,
    name: String,
) -> Result<String, String> {
    match client.get_rendezvous_token(Some(name.clone())).await {
        Ok(code) => {
            *st.pair_arm.lock().unwrap_or_else(|p| p.into_inner()) =
                Some((name.clone(), Instant::now()));
            *st.pair_code.lock().unwrap_or_else(|p| p.into_inner()) =
                Some((name.clone(), code.as_str().to_string(), Instant::now()));
            info!("pairing code issued for {name} (5 min, shown on the page only)");
            Ok(code.as_str().to_string())
        }
        Err(e) => {
            warn!("could not get pairing code: {e}");
            Err(e.to_string())
        }
    }
}

async fn on_pair_request(
    fingerprint: String,
    reply: tokio::sync::oneshot::Sender<FingerprintVerificationReply>,
    st: &Arc<web::AppState>,
) {
    let armed = st
        .pair_arm
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take()
        .filter(|(_, at)| at.elapsed() < PAIR_WINDOW)
        .map(|(name, _)| name);
    let approved = armed.is_some();
    let shown: String = fingerprint.chars().take(12).collect();
    info!(
        "pairing: {} {shown}",
        if approved { "approved" } else { "refused" }
    );
    let _ = st.audit.write(Entry {
        ts: now(),
        kind: "pairing",
        device: armed.as_deref(),
        fingerprint: Some(&fingerprint),
        agent: None,
        requested: None,
        item_id: None,
        item_name: None,
        reason: None,
        outcome: if approved { "approved" } else { "refused" },
        detail: None,
    });
    let _ = reply.send(FingerprintVerificationReply {
        approved,
        name: armed,
    });
}

/// Who may approve. Authentication is the tailnet identity Serve injects
/// (`Tailscale-User-Login`), which a client cannot spoof: Serve strips it from
/// incoming requests and rewrites it. That means the daemon needs to know whose
/// login is the operator, and fails closed without it.
struct Auth {
    owner: String,
    token: String,
    allow_token: bool,
}

fn auth_from_env() -> Result<Auth, BoxError> {
    let owner = std::env::var("AAC_BROKER_OWNER").unwrap_or_default();
    if !owner.contains('@') {
        return Err(
            "AAC_BROKER_OWNER must be set to the tailnet login allowed to approve \
             (e.g. you@example.com): the approval page can release credentials, so it \
             fails closed rather than running unauthenticated"
                .into(),
        );
    }
    let allow_token = std::env::var("AAC_BROKER_ALLOW_TOKEN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let token = std::env::var("AAC_BROKER_TOKEN").unwrap_or_default();
    if allow_token && token.len() < 16 {
        return Err(
            "AAC_BROKER_ALLOW_TOKEN is set but AAC_BROKER_TOKEN is missing or shorter than \
             16 characters"
                .into(),
        );
    }
    Ok(Auth {
        owner,
        token,
        allow_token,
    })
}

async fn serve(proxy_url: String, pair: Option<String>) -> Result<(), BoxError> {
    let auth = auth_from_env()?;
    // The Host header is compared against this value. A wrong or missing host would silently
    // weaken the origin check on a page that can release credentials, so fail closed instead
    // of guessing a hostname.
    let expected_host = std::env::var("AAC_BROKER_HOST").unwrap_or_default();
    if expected_host.is_empty() {
        return Err(
            "AAC_BROKER_HOST must be set to the hostname the approval page is served on \
             (it is compared against the Host header)"
                .into(),
        );
    }
    let pair = pair.or_else(|| {
        std::env::var("AAC_BROKER_PAIR_NAME")
            .ok()
            .filter(|s| !s.is_empty())
    });
    let dir: PathBuf = storage::state_dir()?;
    // The page must not claim "code issued" before the relay has actually
    // produced one, so the request carries a reply channel.
    let (pair_tx, mut pair_rx) = tokio::sync::mpsc::channel::<(
        String,
        tokio::sync::oneshot::Sender<Result<String, String>>,
    )>(4);
    // Revocations must be applied by the loop that owns the relay client, so the
    // client is stopped before the connection store is rewritten.
    let (revoke_tx, mut revoke_rx) = tokio::sync::mpsc::channel::<(
        String,
        tokio::sync::oneshot::Sender<Result<usize, String>>,
    )>(4);

    let collection = std::env::var("AAC_BROKER_COLLECTION_ID")
        .ok()
        .filter(|s| !s.is_empty());
    // Optional: reuse a session the operator already granted, so a restart does
    // not send them back to a password prompt. The stored expiry is absolute, so
    // this restores the window they granted — it never extends it.
    let vault = Arc::new(Vault::new());
    let mut restored_until = 0u64;
    if vault::persist_enabled() {
        match vault.restore_session(&dir).await {
            Ok(exp) => {
                restored_until = exp;
                info!("restored persisted vault session (unlocked until {exp})");
            }
            Err(e) => info!("no persisted vault session: {e}"),
        }
    } else if vault::session_file(&dir).exists() {
        warn!("AAC_BROKER_PERSIST_SESSION is off but a stored session exists; ignoring it");
    }

    let st = Arc::new(web::AppState {
        dir: dir.clone(),
        collection: collection.clone(),
        vault: vault.clone(),
        pending: Arc::new(Pending::default()),
        grants: Arc::new(Grants::load(&dir)),
        audit: Arc::new(Audit::load(&dir)),
        push: Pushover::from_env(),
        unlock_until: std::sync::atomic::AtomicU64::new(0),
        expected_host: expected_host.clone(),
        unlock_lock: tokio::sync::Mutex::new(()),
        owner: auth.owner.clone(),
        token: auth.token,
        allow_token: auth.allow_token,
        unlock_failures: Mutex::new(Vec::new()),
        pair_tx,
        revoke_tx,
        pair_arm: Mutex::new(None),
        pair_code: Mutex::new(None),
    });

    let listen = std::env::var("AAC_BROKER_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_string());
    {
        let st = st.clone();
        let listener = tokio::net::TcpListener::bind(&listen).await?;
        info!(
            "approval page on http://{listen} (owner: {}{})",
            auth.owner,
            if auth.allow_token {
                ", break-glass token enabled"
            } else {
                ""
            }
        );
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, web::router(st)).await {
                warn!("web server stopped: {e}");
            }
        });
    }

    // The page's unlock TTL is enforced here, not by the browser. The lock is
    // taken for the check-and-lock so a concurrent unlock cannot be cleared by
    // a tick that decided to expire a moment earlier.
    {
        let st = st.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                let until = st.unlock_until.load(Ordering::Relaxed);
                if until == 0 || until > now() {
                    continue;
                }
                let _guard = st.unlock_lock.lock().await;
                if st.unlock_until.load(Ordering::Relaxed) > now() {
                    continue; // an unlock landed while we waited
                }
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
                    detail: Some("ttl expired"),
                });
                st.vault.forget_session(&st.dir);
                if let Some(p) = &st.push {
                    p.notify("aac-broker: vault locked", "Unlock TTL expired.", None);
                }
            }
        });
    }

    // Retention, on a timer: a long-lived process must not keep everything
    // forever just because it never restarted.
    {
        let audit = st.audit.clone();
        tokio::spawn(async move {
            let mut daily = tokio::time::interval(Duration::from_secs(24 * 3600));
            loop {
                daily.tick().await;
                audit.prune(audit::RETENTION_DAYS);
            }
        });
    }

    let svc = Arc::new(Service {
        st: st.clone(),
        dir: dir.clone(),
        collection,
        approval_timeout: std::env::var("AAC_BROKER_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(pending::DEFAULT_APPROVAL_TIMEOUT),
        sem: Arc::new(Semaphore::new(
            std::env::var("AAC_BROKER_MAX_IN_FLIGHT")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(MAX_IN_FLIGHT),
        )),
    });
    if restored_until > 0 {
        st.unlock_until.store(restored_until, std::sync::atomic::Ordering::Relaxed);
    }
    if svc.collection.is_none() {
        warn!("AAC_BROKER_COLLECTION_ID is unset: domain lookup runs across the whole vault");
    }
    info!("state dir: {}", dir.display());
    info!("relay: {proxy_url}");

    let mut backoff = Duration::from_secs(2);
    loop {
        let handle = match connect(&dir, &proxy_url).await {
            Ok(h) => h,
            Err(e) => {
                warn!(
                    "relay connect failed: {e}; retrying in {}s",
                    backoff.as_secs()
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(120));
                continue;
            }
        };
        backoff = Duration::from_secs(2);
        info!("relay connected");
        let UserClientHandle {
            client,
            mut notifications,
            mut requests,
        } = handle;

        if let Some(name) = pair.as_deref() {
            let _ = issue_code(&client, &st, name.to_string()).await;
        }

        loop {
            tokio::select! {
                n = notifications.recv() => match n {
                    Some(UserClientNotification::Reconnecting { attempt }) => {
                        warn!("relay reconnecting (attempt {attempt})");
                        if let Some(p) = &svc.st.push {
                            p.notify(
                                "aac-broker: relay reconnecting",
                                "The relay link dropped; approvals may be delayed.",
                                None,
                            );
                        }
                    }
                    Some(UserClientNotification::Reconnected {}) => info!("relay reconnected"),
                    Some(UserClientNotification::ClientDisconnected {}) => {
                        info!("agent disconnected");
                    }
                    Some(UserClientNotification::Error { message, context }) => {
                        warn!("client error: {message} ({})", context.unwrap_or_default());
                    }
                    Some(_) => {}
                    None => {
                        warn!("notification stream ended");
                        break;
                    }
                },
                Some((name, reply)) = pair_rx.recv() => {
                    let outcome = issue_code(&client, &st, name).await;
                    let _ = reply.send(outcome);
                }
                Some((key, reply)) = revoke_rx.recv() => {
                    // Stop the client first: it holds the connection set in memory
                    // and rewrites it on the next update, which would resurrect the
                    // pairing we are removing.
                    drop(requests);
                    drop(notifications);
                    drop(client);
                    let outcome = match FileConnections::load(&dir) {
                        Ok(mut conns) => conns.remove(&key).map_err(|e| e.to_string()),
                        Err(e) => Err(e.to_string()),
                    };
                    match outcome {
                        Ok(n) => {
                            if n > 0 {
                                let dropped = st.pending.expire_for(&key);
                                // A revoked device's approvals are both useless
                                // and a record of what it could read.
                                let forgotten = st.grants.forget_device(&key);
                                info!("unpaired {key}: {n} connection(s), {dropped} waiting request(s) dropped, {forgotten} approval(s) cleared");
                            }
                            let _ = reply.send(Ok(n));
                        }
                        Err(e) => {
                            warn!("unpair failed: {e}");
                            let _ = reply.send(Err(e));
                        }
                    }
                    break;
                }
                r = requests.recv() => match r {
                    Some(UserClientRequest::VerifyFingerprint { fingerprint, reply, .. }) => {
                        on_pair_request(fingerprint, reply, &st).await;
                    }
                    Some(UserClientRequest::CredentialRequest { query, identity, reply }) => {
                        // Never await an approval inside this select: that would
                        // stop pairing and every other agent for up to the whole
                        // timeout. Spawn it, bounded by the semaphore.
                        let svc = svc.clone();
                        match svc.sem.clone().try_acquire_owned() {
                            Ok(permit) => {
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    svc.handle(query, identity, reply).await;
                                });
                            }
                            Err(_) => {
                                warn!("too many requests in flight; denying");
                                let _ = reply.send(CredentialRequestReply {
                                    approved: false,
                                    credential: None,
                                    credential_id: None,
                                });
                            }
                        }
                    }
                    None => {
                        warn!("request stream ended");
                        break;
                    }
                },
            }
        }
        warn!("connection dropped; reconnecting");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn vault_status() -> Result<(), BoxError> {
    let v = Vault::new();
    match v.status().await {
        Ok(state) => {
            println!("{state:?}");
            Ok(())
        }
        Err(e) => Err(format!("bw status failed: {e}").into()),
    }
}

fn list_grants() -> Result<(), BoxError> {
    let dir = storage::state_dir()?;
    let grants = Grants::load(&dir);
    let active = grants.active();
    if active.is_empty() {
        println!("no remembered approvals");
        return Ok(());
    }
    for g in active {
        let when = if g.permanent {
            "never (permanent)".to_string()
        } else {
            g.expires_at.to_string()
        };
        println!(
            "{} ({}) -> {} via {} ({}) expires {}",
            g.agent,
            g.fingerprint.chars().take(12).collect::<String>(),
            g.item_name,
            g.domain.as_deref().unwrap_or("-"),
            g.item_id,
            when
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    match Cli::parse().cmd {
        Cmd::Serve { proxy_url, pair } => serve(proxy_url, pair).await,
        Cmd::VaultStatus => vault_status().await,
        Cmd::Grants => list_grants(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: &str, name: &str, uris: &[&str]) -> Candidate {
        Candidate {
            id: id.to_string(),
            name: name.to_string(),
            username: Some("u@example.com".to_string()),
            uris: uris.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn ask_parsing_handles_all_three_shapes() {
        let a = parse_ask("github.com | hermes | check gh auth");
        assert_eq!(a.what, "github.com");
        assert_eq!(a.agent.as_deref(), Some("hermes"));
        assert_eq!(a.reason.as_deref(), Some("check gh auth"));

        let b = parse_ask("github.com | because I said so");
        assert_eq!(b.what, "github.com");
        assert_eq!(b.agent, None);
        assert_eq!(b.reason.as_deref(), Some("because I said so"));

        let c = parse_ask("github.com");
        assert_eq!(c.what, "github.com");
        assert!(c.agent.is_none() && c.reason.is_none());
    }

    #[test]
    fn ask_parsing_strips_control_characters_and_caps_length() {
        let a = parse_ask("github.com | her\u{7}mes | line\nbreak");
        assert_eq!(a.agent.as_deref(), Some("hermes"));
        assert_eq!(a.reason.as_deref(), Some("linebreak"));
        let long = "a".repeat(10_000);
        assert!(parse_ask(&long).what.len() <= MAX_QUERY);
    }

    #[test]
    fn host_extraction_normalises_scheme_case_userinfo_port_and_trailing_dot() {
        assert_eq!(host_of("HTTPS://GitHub.com/login?x=1"), "github.com");
        assert_eq!(host_of("github.com"), "github.com");
        assert_eq!(host_of("https://user:pw@github.com:443/x"), "github.com");
        assert_eq!(host_of("https://github.com."), "github.com");
    }

    #[test]
    fn an_exact_host_match_sorts_first_but_nothing_is_hidden() {
        // The operator decides: every hit is offered, the best host match first.
        let cs = vec![
            cand("1", "GitHub Backup", &["https://backup.example"]),
            cand("2", "GitHub", &["https://github.com"]),
        ];
        let got = rank_candidates(&cs, "github.com");
        assert_eq!(got.len(), 2, "no item is dropped for a different host");
        assert_eq!(got[0].id, "2", "exact host match first");
    }

    #[test]
    fn sub_and_super_domains_rank_above_unrelated_items() {
        let cs = vec![
            cand("u", "Unrelated", &["https://example.net"]),
            cand("s", "RACV www", &["https://www.racv.com.au"]),
            cand("e", "RACV", &["https://racv.com.au"]),
        ];
        let got = rank_candidates(&cs, "racv.com.au");
        assert_eq!(got[0].id, "e", "exact first");
        assert_eq!(got[1].id, "s", "then the subdomain");
        assert_eq!(got[2].id, "u", "an unrelated hit is still offered");
    }

    #[test]
    fn every_item_for_one_host_is_offered_for_the_operator_to_pick() {
        // Several matches is not an error: the page lists them and the human
        // chooses. What must never happen is a silent pick.
        let cs = vec![
            cand("1", "GitHub work", &["https://github.com"]),
            cand("2", "GitHub personal", &["https://github.com"]),
            cand("3", "GitHub old", &["https://github.com/login"]),
        ];
        let got = rank_candidates(&cs, "github.com");
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn a_fuzzy_hit_is_offered_but_ranked_last() {
        // Was a hard filter: a lone substring hit with a different host was
        // dropped, which is why a vault storing www.racv.com.au refused a
        // request for racv.com.au. Now it is offered, marked similar in the UI.
        let cs = vec![cand("1", "RACV", &["https://www.racv.com.au"])];
        let got = rank_candidates(&cs, "racv.com.au");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "1");
    }

    #[test]
    fn candidates_are_capped_so_the_picker_stays_a_decision() {
        let cs: Vec<Candidate> = (0..40)
            .map(|i| cand(&i.to_string(), "x", &["https://github.com"]))
            .collect();
        assert_eq!(rank_candidates(&cs, "github.com").len(), MAX_CANDIDATES);
    }

    #[test]
    fn a_bare_suffix_never_counts_as_a_host_match_but_is_still_listed() {
        // Ranking, not filtering: the scores must distinguish a real host match
        // from a coincidental suffix, and the item stays on the list either way.
        let cs = vec![cand("1", "Bank", &["https://bank.example.com"])];
        assert_eq!(rank_candidates(&cs, "com")[0].id, "1");
        assert_eq!(rank_candidates(&cs, "bank.example.com")[0].id, "1");
        // score, not membership
        assert_eq!(host_score("bank.example.com", "com", "com"), 0);
        assert_eq!(host_score("bank.example.com", "bank.example.com", "example.com"), 3);
        assert_eq!(host_score("bank.example.com", "example.com", "example.com"), 2);
    }

    #[test]
    fn empty_or_garbage_domain_never_matches() {
        let cs = vec![cand("1", "GitHub", &["https://github.com"])];
        assert!(rank_candidates(&[], "github.com").is_empty());
        // an empty ask cannot score anything, so nothing is preferred
        assert_eq!(host_score("github.com", "", ""), 0);
        assert!(rank_candidates(&cs, "   ")[0].uris[0].contains("github"));
    }
}
