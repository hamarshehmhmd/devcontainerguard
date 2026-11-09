# Contributing

Thanks for helping! Issues and PRs are welcome, especially new rules and false-positive reports.

## Development

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
cargo run -- tests/fixtures      # try it on the fixtures
```

All three checks must pass; CI runs them on Linux, macOS and Windows.

## Project layout

| Path | What |
|------|------|
| `src/jsonc.rs` | JSONC parser with positions and comments |
| `src/rules.rs` | Rule catalogue (`RULES`) and `check()` |
| `src/lib.rs` | `lint_str`, inline ignores, file discovery |
| `src/config.rs` | `.devcontainerguard.yaml` |
| `src/output.rs` | human / json / sarif / github formatters |
| `tests/fixtures/` | sample devcontainers (insecure, secure, agent sandbox, feature, ignores) |

## Adding a rule

1. Open a "New rule" issue first if the rule is non-obvious, so we can agree on scope and severity.
2. Add an entry to the `rules!` table in `src/rules.rs` with the next free ID (`DCG0xx`). IDs are stable and never reused or renumbered.
3. Implement the check in `check()`. Report the position of the most specific node (array element or value) so `line:column` and inline ignores are precise.
4. Make `tests/fixtures/insecure/.devcontainer/devcontainer.json` trigger it, add a focused test in `tests/lint.rs`, and make sure the `secure/` and `agent-sandbox/` fixtures stay clean.
5. Document it in `docs/rules.md`, the README table and `CHANGELOG.md`.

Keep false positives low: when in doubt, prefer `info` severity. Never print secret values in messages.

## Commits and PRs

- Small, focused PRs with a clear description; fill in the PR template.
- Conventional-ish commit subjects (`feat:`, `fix:`, `docs:`, `ci:`) are appreciated.
- By contributing you agree your work is licensed under the MIT license.
