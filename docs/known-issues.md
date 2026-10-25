# Known issues

Findings from a read-only review of this code (2026-10-25) that are **not** fixed yet, plus the ones
that are, so nobody has to rediscover them.

## Open

### A request that arrives while the vault is locked can lose its query

`ask.what` is a human label (`item <id>` or `search "<term>"`). When a request is held because the
vault is locked, unlocking re-derives the query from that label, so an id query can be reissued as a
domain query and vice versa. An empty result does not deny or fill the card, so it can sit on "vault
locked" after a successful unlock. The timeout detail is also written from the lock flag captured at
arrival, so a window in which the operator did unlock may still be audited as "the vault was locked
for the whole window".

Impact: a stalled card and a misleading audit line — not a wrong release. Fix: carry the original
query kind and value on the pending record, and read the vault state at expiry rather than at
arrival.

## Fixed in this tree (2026-10-25, with regression tests)

- **A remembered grant could release a different site's credential.** Auto-release matched on
  `(device, item id)` only, and Bitwarden's search is a substring match, so a query that merely
  surfaced the item could release it with no card. Auto-release now requires the item to list the
  requested host *and* the grant to have been made for that host; an `item <id>` query can never
  auto-release.
- **`registrable()` returned the last two labels**, so `www.racv.com.au` became `com.au` and the
  fallback search matched an entire country. Multi-label suffixes are recognised, a bare public
  suffix returns no domain, and a public suffix can never score as a host match.
- **`POST /device/revoke` skipped the origin check** that every other state-changing POST has.
- **A failed grants write reported success.** `revoke`, `forget_device` and the remember paths now
  propagate I/O errors, and the page refuses to claim an approval was saved when it was not.
- **Grants were checked without their site**, so the same item id on another host passed.
- **`bw get item` ignores collection scoping**, so an id query could reach an item outside the
  configured collection; membership is now verified.
- **Two pending requests from one device in the same second shared an id**, and the loser's expiry
  removed the survivor.
- **The first radio on a multi-item card was pre-checked**, which made a near-match the default
  approval. Only an exact host match is pre-selected now.
- **The unit ran as root** while holding a vault session; it now runs as a dedicated user with
  `UMask=0077`.
- **The Pushover body carried the vault username**, which a third party stores; the tailnet page
  keeps that detail.
