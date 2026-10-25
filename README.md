# aac-broker

![WARNING: this can send your real password to an AI agent. Only after you approve a request and only for the item you name — but approve the wrong request, or let the agent be fooled or compromised, and that password leaves your vault and sits in that program's environment. Start with a throwaway login; not your bank, not your email, not your only copy. Provided as-is, with no warranty; if a credential leaks that is your risk to carry. See the licence, sections 7 and 8.](assets/warning.svg)

> [!WARNING]
> **This can hand a real password to an AI agent.**
>
> Read this before you install it. This tool takes a password out of your vault and puts it into a
> running process on an agent's machine. It does that only after you approve a request, and only for the
> one item you name — but if you approve the wrong request, or the agent is confused, manipulated, or
> compromised, that password leaves your vault and lives in that process's environment until it exits.
>
> **Start with a throwaway login item.** Not your bank, not your email, not the only copy of anything.
> Watch the audit trail. Then decide whether a second one is worth it.
>
> There is **no warranty and no responsibility taken**. If a credential leaks, that is your risk to
> carry. The licence says this in legal terms (Apache-2.0, sections 7 and 8); this box says it plainly
> because it is the part that matters.

## What this actually does, in plain language

You have a password manager. An AI agent — a program that thinks for itself — needs to log into a
website to do a job for you. Handing it the password by pasting it in is how passwords end up in logs
and chat history, so Bitwarden built **Agent Access**: the agent asks, you approve, and the password is
delivered straight into the program without ever being printed.

The problem: Bitwarden 0.11 only gives *you* a terminal window to approve in. No phone notification, no
browser page, nothing you can tap while you are out of the house. So this project replaces that terminal
window with a web page only your private network can reach, plus a phone notification that something
wants a credential.

The exchange, end to end: the agent asks for `github.com` and says why. Your phone buzzes. You open the
page on your own device, see which **device** is asking (verified by its key), which **agent** it claims
to be (not verified — it is a claim), and which vault **item** would be released. You pick the item, or
deny. The password is handed to that one process, and a line is written to an audit trail saying which
device got which item and when.

Nothing here can approve anything without your own device's identity, and nothing is released without
you naming the item.

## Why this exists — and what I would rather have

**I would rather Bitwarden shipped this in the app.** A native approval page, push notifications, and
an approval API belong in the product, not in a side project one person maintains. Agent Access is
useless to anyone who is not sitting at a terminal without it, which is most of the point of an agent.

So: this is a stopgap. It tracks a pinned preview release (`ap-client = "=0.11.0"`), the protocol is v0
draft, and the honest plan is to delete this repo the day the feature lands upstream. Upstream context:
[#147](https://github.com/bitwarden/agent-access/issues/147),
[#142](https://github.com/bitwarden/agent-access/issues/142),
[#148](https://github.com/bitwarden/agent-access/issues/148).

Not affiliated with or endorsed by Bitwarden. If you work on Agent Access and want any of this
upstream, take it — the licence already allows it, and I would rather help than compete.

## What it is, technically

Approval broker for [Bitwarden Agent Access](https://github.com/bitwarden/agent-access)
(`aac`): answers credential requests from agents without a terminal TUI in the loop.

Bitwarden 0.11 only ships a ratatui TUI as the user side — no headless mode, no
out-of-band notification, no approval API.
This replaces the TUI with a background `UserClient` from the official `ap-client` SDK:
requests arrive as protocol messages, get resolved against an **item-ID allowlist**, and
are released only after an explicit approval on a tailnet-only page, with a Pushover
doorbell and a full audit trail.

## Status

Working end to end: agent asks → request lands on a tailnet-only page → operator approves
or denies → credential is released or refused, with an audit line either way. Verified
against a live vault in daily use since 2026-10-23, both approve and deny paths.

What it does not do yet: collection-scoped lookup (env var exists, unset), a device list on
the page, and Windows agent hosts.

## Endpoints (127.0.0.1, published with `tailscale serve`)

| Route | Purpose |
|---|---|
| `GET /` | pending queue, unlock form, live grants, audit tail, pair form |
| `POST /unlock` | master password + TTL (1/2/4/8h, default 2h) |
| `POST /lock` | lock immediately |
| `POST /decision` | approve / deny, optional remember (15 min, 1 hour) |
| `POST /grant/revoke` | drop a remembered approval |
| `POST /pair` | mint a pairing code for a device without restarting the service |
| `GET /healthz` | liveness |

## Configuration

Environment (systemd `EnvironmentFile`):

| Variable | Meaning |
|---|---|
| `AAC_BROKER_STATE_DIR` | identity, connections, audit, grants (0700) |
| `AAC_BROKER_LISTEN` | default `127.0.0.1:8787` |
| `AAC_BROKER_HOST` | expected host for the same-origin check on POSTs |
| `AAC_BROKER_PUBLIC_URL` | link used in the push notification |
| `AAC_BROKER_COLLECTION_ID` | confine domain lookup to one collection |
| `AAC_BROKER_OWNER` | **required** — the tailnet login allowed to approve (`you@example.com`). Authentication is the `Tailscale-User-Login` header that Serve injects and clients cannot spoof; the daemon refuses to start without it |
| `AAC_BROKER_ALLOW_TOKEN` | `1` enables the break-glass bearer path (default off) |
| `AAC_BROKER_TOKEN` | break-glass token, only honoured when `AAC_BROKER_ALLOW_TOKEN=1` |
| `AAC_BROKER_TIMEOUT` | approval window in seconds (default 120) |
| `PUSHOVER_TOKEN` / `PUSHOVER_USER` | doorbell; absent means no notifications |
| `PUSHOVER_SOUND` | Pushover sound name (default `bike` — a light bell) |
| `PUSHOVER_PRIORITY` | `-2..2`, default `0`; `1` bypasses quiet hours, so raise it deliberately |
| `HOME`, `BW_CONFIG_DIR` | **required** — without `HOME`, `bw` writes to `/.config` and dies |

## Build

Requires a Rust toolchain and `pkg-config` + OpenSSL headers.

```bash
apt-get install -y pkg-config libssl-dev
cargo build --release
```

## Use

```bash
# Listen, and arm a one-time pairing code for a device name
aac-broker serve --pair hermes-lxc

# On the agent host, using the printed code:
aac connect --token ABC-DEF-GHI --domain example.com --output json
```

State (identity key, paired devices) lives in `$AAC_BROKER_STATE_DIR`
(default `$XDG_DATA_HOME/aac-broker`), mode 0700, files 0600.

## For agents

- [`docs/agent-integration.md`](docs/agent-integration.md) — the spec to hand to another agent or
  implementer: call shape, injected environment, failure semantics, pairing a host, and the
  invariants if they build their own broker.
- [`deploy/aac-cred`](deploy/aac-cred) — the wrapper every paired host runs:
  `aac-cred github.com "check gh auth" -- gh auth status`.

## Activity log

Recent activity is newest-first, 25 entries to a page, with the time rendered in the
viewer's own timezone (the file stores epoch seconds; the page rewrites them client-side and
keeps the ISO value in the tooltip). Each line is clickable and expands to the whole record —
every field in the audit entry, not a summary of the visible columns.

## Pairing a device

Asking for a code waits for the relay's answer before reporting success, so the code is on the
page by the time the redirect lands. The code panel shows the exact command for the host
(`aac connect --token <code>`), a copy button, the seconds left, and **reissue** / **cancel code**;
after five minutes it says the code expired, with a fresh-code button and a clear action.

Cancelling clears the broker's arming for the next fingerprint verification, which is what
actually authorises a pairing. The relay owns the code and keeps it until its own five-minute
expiry, so whatever holds the code can still present it — it will simply be **refused**. A
cancelled code is audited as `kind: pairing, outcome: cancelled` with the actor.

## Approving a site permanently

The approval card's **remember** menu offers `this once`, `15 min`, `1 hour` and
**`always — permanent`**. A permanent approval is a grant with `permanent: true`:
it never expires, is never pruned, and ends only when revoked by hand. It is
still scoped to one `(device fingerprint, vault item)` pair — approving
`github.com` permanently for `hermes-lxc` does not approve it for `grokbot`, and
does not touch the other GitHub logins in the vault. If a request matches several
items and more than one is approved, the picker still appears rather than guessing.

Grants record the domain they were approved for, so the device view reads as a
site rather than an opaque item id.

## Approvals live under the device

Each paired device on the page is a disclosure: click it open to see that
device's approvals — site, item, and either `permanent` or the time left — each
with a revoke button, plus the unpair control. Unpairing also clears that
device's approvals: a revoked device's list is both useless and a record of what
it was allowed to read.

## Revoking a device

The page lists paired devices with their fingerprint, pairing date and last use.
**Unpair** removes a device's connection record; that host is then refused by the
relay and must pair again with a fresh code.

The removal is performed by the service loop, never by the web handler, because
the relay client holds the connection set in memory and rewrites the file on its
next update — editing under a live client lets it write the pairing back. So the
loop stops the client first, rewrites the store, drops any of that device's
waiting requests, then reconnects (~2s of relay downtime). The form requires the
confirm checkbox, so a stray tap on a phone cannot unpair anything.

## Nothing is filtered out — you decide

The vault lookup is a substring search (`bw list items --search <host>`). Its hits are **ranked, not
filtered**: an item whose host differs from the requested one is still offered, so a request for
`racv.com.au` finds an item stored as `www.racv.com.au`. Order is exact host, then sub/super-domain,
then same registrable domain, then everything else; the list is capped at 12.

The card says which is which: an item that does not match the host exactly carries a **similar**
tag and the card states `no exact host match for <host> — this is what the vault returned`, with the
item's real URI shown. A bare TLD (`com`) never scores as a host match. If the narrow term returns
nothing at all, the lookup is retried with the registrable domain before giving up.

The safety property is unchanged: a remembered or permanent approval only auto-releases when exactly
one candidate is approved, and nothing is ever released as a set.

## Not typing the master password every time

Three options, cheapest first.

**1. Phone autofill (no code, no new risk).** The unlock field is a standard
`autocomplete="current-password"` input, so Bitwarden on your phone offers the item with Face ID.
Create one login item for the broker page (name `aac-broker`, username `owner@example.com`, password
= the master password) and autofill fills it: a face, not a keyboard.

**2. Persist the session (one flag).** `AAC_BROKER_PERSIST_SESSION=1` writes the session key to
`$STATE_DIR/bw-session.json` (0600) with the **absolute** expiry of the unlock you granted. A restart
then reuses that window instead of re-locking; the expiry is never extended by a restart, an expired
or rejected key is deleted on sight, and the key is re-validated with `bw status` before it is
trusted. The trade is explicit: the file *is* the vault key at rest, so root on this host could read
the vault without the password. Off by default. On lock (manual or TTL) the file is deleted.

**3. Secrets Manager (the clean answer, not built).** Bitwarden's machine accounts (`bws`, access
tokens) hold secrets per project with no vault and no master password at all — a token that can be
revoked. It needs a different backend: a project of agent credentials, named by convention
(`github.com/hermes`), and `bws secret list` instead of `bw list items`. That is the right long-term
shape for agent access; it is a separate piece of work.

Passkeys cannot unlock the CLI: the `bw` CLI has no WebAuthn support, and a passkey's PRF unlocks
only the client that performs the assertion. A key in your iPhone's keychain cannot be used by a
server process without implementing CTAP2 and PRF ourselves, which is not something to hand-roll.

## A locked vault holds the request

A locked vault cannot resolve an item — but that is not a reason to throw the request away, so it
is **held** instead of denied. The card appears immediately with what is known without the vault
(device, claimed agent, requested host, reason) and an unlock form on the card itself. Unlocking
resolves the held requests, then the card becomes a normal approval.

Consequences, stated because they are trade-offs rather than bugs:

- While locked, the card names the **host** but not the item or username — you unlock partly on
  trust when a host has several logins.
- Nothing can be approved until the candidates are known, so a locked card offers only **Deny**.
- If the vault stays locked for the whole window the request is denied at timeout, audited as
  `outcome: timeout` with `detail: "no decision; the vault was locked for the whole window"` — not
  a bare denial.
- The service's own candidate snapshot can be empty at decision time, so the waiting side consumes
  the candidates carried by the decision (`pending::Decision`), which are the ones the operator
  actually saw.

## Security model

- Trusted: the operator's Tailscale identity. Untrusted: agents, the machines they run on,
  the relay, and any other tailnet peer. Every route except `/healthz` requires the
  `Tailscale-User-Login` header to equal `AAC_BROKER_OWNER`. Serve injects that header for
  user-owned devices and strips client-supplied copies, so it is verified identity rather
  than a shared secret — and **tagged devices get no identity header**, so an agent host
  cannot approve its own request. A local process inside the container can forge both the
  header and `X-Forwarded-For`; that is root-in-the-box and out of scope. `AAC_BROKER_ALLOW_TOKEN=1`
  turns the old bearer token back on as break-glass for an auth outage, and it is audited as
  `break-glass token`.
- A domain request only considers vault items whose **normalised host equals the requested
  host** — no first-match, no suffix match, and a lone fuzzy search hit is not a match. If
  several items match, the page lists them and the operator picks which one is released;
  an approval that names no item is rejected.
- Grants are keyed on the **device fingerprint**, not the display name, so a second device
  paired under an existing name inherits nothing.
- The audit trail records the fingerprint, and delivery is recorded after a successful send
  (`released`), separately from the authorisation (`allowed`). Pairing, grants and revokes
  are audited too.
- Unlock is rate limited: five failures in ten minutes locks the form out.
- The relay carries only Noise ciphertext; it can see who talks to whom, not what.
- Agent-supplied context (`item | agent | reason`) is a claim. The device fingerprint from
  pairing is the verified field.
- Notes fields are never released — they can hold recovery codes.
- Default deny: unknown domains, unknown items, timeouts, and a locked vault all deny.

## Test

```bash
cargo test          # unit tests: policy, pending, vault, audit, push, and the page's render + auth paths
cargo clippy --all-targets -- -D warnings
bash scripts/leak-scan.sh   # refuses to publish anything carrying a private detail
```

CI runs all three on every push (staged — see `CI.md`), and
`git config core.hooksPath .githooks` puts the leak scan in front of every commit.

## Origin

Extracted from a working private deployment and sanitised for publication: one operator, one
vault, agents that ask for credentials and a page that decides. Estate-specific values are gone
(hostnames, owner addresses, fixture IPs are RFC 5737 documentation ranges) and
`AAC_BROKER_HOST` is required rather than defaulted, so a deployment cannot accidentally inherit
somebody else's origin check.

Written by an AI agent working for its operator, and reviewed by them. Bug reports and design
disagreements are welcome — especially about the release rules above, which are the part that
matters.

## Licence

Apache-2.0. The relay/tunnel handling and the file-backed identity and connection stores
are adapted from [`aac-touchid`](https://github.com/justmytwospence/aac-touchid)
(Apache-2.0) and Bitwarden's `ap-cli` (Apache-2.0); see `NOTICE`.

**No responsibility is accepted for what this does with your credentials.** The software is provided
"AS IS", without warranties or conditions of any kind, and in no event shall the author be liable for
any claim, damage, credential disclosure, account compromise, or other liability arising from its use —
sections 7 and 8 of the licence are the operative text, and they are not boilerplate here. You are
running a program that releases passwords to other programs. Decide deliberately, test with a
throwaway item, and keep the audit trail.
