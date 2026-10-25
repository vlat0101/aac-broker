# Agent integration

You are an agent that needs a password, token or 2FA code. This document is your spec. It assumes
an `aac-broker` is already running and a human is reachable to approve requests.

## 1. What the broker is, in one paragraph

`aac-broker` speaks Bitwarden's Agent Access protocol. It holds a vault session, receives
credential requests from paired agent hosts over an end-to-end encrypted relay, asks a human to
approve on a web page, and returns the credential **inside the encrypted channel** — to a child
process environment, not to your context window. You never see the vault, the relay never sees the
secret, and a human sees every request with your name, the item, and the reason you gave.

## 2. Your call shape

```bash
aac-cred <domain> "<why>" -- <command>
```

`aac-cred` is a thin wrapper around:

```bash
aac run --session <broker-fingerprint> --domain "<domain> | <agent-name> | <why>" --env-all -- <command>
```

Do not hand-roll that. If `aac-cred` is not on the host, the host is not paired — stop and report;
do not improvise an alternative credential path.

### Environment injected into `<command>`

| Variable | Contents |
|---|---|
| `AAC_USERNAME` | login name |
| `AAC_PASSWORD` | password |
| `AAC_TOTP` | current TOTP code, if the item has one |
| `AAC_URI` | the item's URI |
| `AAC_DOMAIN` | the domain you requested |
| `AAC_CREDENTIAL_ID` | vault item id |

## 3. Hard rules

1. **No secret in your output.** Not printed, not logged, not written to a file, not put in a URL,
   not summarised into a report. Consume it in the child process and let it die there.
2. **Never ask the human to paste a password.** The page approval is the consent mechanism.
3. **`aac run`/`aac-cred` only.** `aac connect --output json` prints the password to stdout;
   `aac listen` is the broker's own mode; `--ephemeral-connection` skips saved pairings and fails.
4. **One request per action.** Every request is a phone notification. A retry loop is spam; if a
   call fails, diagnose, then ask at most once more.
5. **A denial is final.** No filesystem scavenging for `.env`, `~/.netrc`, browser stores, or
   guessed defaults.
6. **Always pass `--session`.** With more than one paired listener, `aac` refuses to choose.

## 4. Failure semantics

| Exit | Meaning | Action |
|---|---|---|
| 0 | credential released, command ran | use the command's output |
| 4 | denied by the operator, or the approval window expired | report "denied/timed out" and stop |
| other | transport/CLI error | report it; the broker may be down |

A locked vault denies **instantly**, and the operator is pushed a "request while locked" alert.
That is not a bug to work around — tell them to unlock the page.

## 5. Domain string

- Bare lowercase host: `github.com`, `api.stripe.com`, `github.com`.
- Release requires a vault item whose URI host matches **exactly** after normalisation (scheme,
  userinfo, port, trailing dot ignored). No substring or suffix matching.
- If several items match the host, the page lists them all and the human picks one. You do not
  specify an account.
- Write the reason as a human would read it: `"check gh auth status"`, not `"needed"`.

## 6. Pairing a new host (needs the operator)

1. Operator: broker page → **Pair a device** → name it → a 5-minute code appears.
2. Host: install `aac` (release tarball for the architecture), then `aac connect --token <code>`
   once. The connection is saved under the host's XDG data dir.
3. Host: drop `aac-cred` in `/usr/local/bin`, and write the **broker's** fingerprint into
   `${XDG_STATE_HOME:-$HOME/.local/state}/aac-broker-peer` (or export `AAC_SESSION`). The fingerprint is the broker's
   identity — identical from every requester.

Each host is audited separately and carries its own grants, keyed by device fingerprint.

## 7. If you are implementing a broker, not using one

The minimum viable shape, in the order that matters:

1. **Identity and pairing.** `ap-client`'s `UserClient` (Rust) or the UniFFI bindings. You need
   persistent identity storage, a connection store, and a 5-minute pairing window that approves the
   next fingerprint verification only when an operator armed it.
2. **Never block the relay loop.** `CredentialRequest` arrives on a stream; spawn it under a
   concurrency limit. Awaiting a human inside the select stops pairing and every other agent.
3. **Resolve narrowly.** `bw list items --search` is a substring search. Normalise hosts and treat
   only exact matches as candidates; several matches is a *picker*, zero is a denial.
4. **Two records per release.** `allowed` is authorisation, `released` is delivery — written after
   the send succeeds, with the device fingerprint. A failed append must deny.
5. **Authenticate the approver, not the network.** Reachability on a private network is not
   identity. Use the identity the transport asserts (here: Tailscale Serve's `Tailscale-User-Login`,
   which clients cannot spoof and tagged machines never receive — so an agent cannot approve its own
   request), and keep a break-glass path that is off by default and audited as such.
6. **No master password on disk.** Unlock on demand through the authenticated page, with a TTL
   enforced server-side, and lock again automatically.
7. **Never release `notes`.** Recovery codes live there. The credential type should have no field
   for them, so a caller cannot ask.

## 8. Copy-paste block for another agent's instructions

> When a task needs a login, token or API password, run
> `aac-cred <bare-domain> "<one-line reason>" -- <command>`. The credential arrives as
> `AAC_USERNAME` / `AAC_PASSWORD` / `AAC_TOTP` in the child process environment — never print,
> log, or store it, and never ask the user to paste a password. A human approves on their phone
> within 120 seconds; exit code 4 means denied or timed out, and you should report that and stop
> rather than retrying or looking for credentials elsewhere. If `aac-cred` is missing, the host
> is not paired: say so and stop.
