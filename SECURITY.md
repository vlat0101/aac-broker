# Security policy

This project sits between an AI agent and a password vault. It can release real credentials. Treat a
finding here as serious even when it looks small: the failure mode is not a wrong pixel, it is somebody
else's password in an agent's environment.

## Reporting

Open a private security advisory on this repository (Security → Advisories → New draft advisory) rather
than a public issue. If advisories are unavailable, a minimal public issue saying you have a report and
want a channel is enough — no details in it.

Please include: the version or commit, the route or function, what you expected, what happened, and a
reproduction if you have one. A proof-of-concept that releases a credential is welcome; one that uses a
real person's credential is not.

## What is in scope

- Any path that releases a credential without an explicit operator approval naming the item.
- Identity or origin bypasses: a request that is treated as the operator without the operator's device
  asserting it, or a `Host`/`Origin` check that can be defeated.
- Anything that writes a secret where it can be read later — logs, the audit trail, tmp files, argv.
- Grants that outlive their stated window, or survive a revoke.
- The pairing flow: a code that can be reused, or an arm that outlives its code.

## What is not in scope

- The `aac` CLI or the Agent Access protocol itself — report those to
  [Bitwarden](https://github.com/bitwarden/agent-access).
- Deployments that run the page without a private network in front of it, or that enable the break-glass
  token and leave it set. The README says why both are required; a copy that ignores that is a
  configuration problem, not a vulnerability — though tell us if the defaults made it too easy.
- A compromised operator device. Once the operator's own device is attacker-controlled, approval means
  nothing; that is out of reach by design.

## Supported versions

There is one branch, `main`. Fixes land there; there are no backports to releases, because there are no
releases.
