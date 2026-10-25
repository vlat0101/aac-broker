# CI is staged, not enabled

> Moved out of `.github/workflows/` on purpose: GitHub refuses **any** file under that path from a
token without the `workflow` scope, including this note.


`ci.yml.template` at the repo root is the real workflow: `cargo test`, `cargo clippy -D warnings`,
the leak scan, and a `rustsec` audit.

It is not in `.github/workflows/` yet because pushing a workflow file requires a GitHub token with
the **`workflow`** scope, which the token used to publish this repo does not have. The checks still
run locally and `.githooks/pre-commit` runs the leak scan on every commit:

```bash
git config core.hooksPath .githooks     # once, after cloning
```

To turn on Actions: move `ci.yml.template` to `.github/workflows/ci.yml` and push with a token that
has the `workflow` scope (or add the file through the GitHub web UI).
