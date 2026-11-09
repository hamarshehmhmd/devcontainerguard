# devcontainerguard

[![CI](https://github.com/hamarshehmhmd/devcontainerguard/actions/workflows/ci.yml/badge.svg)](https://github.com/hamarshehmhmd/devcontainerguard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/hamarshehmhmd/devcontainerguard)](https://github.com/hamarshehmhmd/devcontainerguard/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-informational)](#github-actions)

**A fast, single-binary security linter for `devcontainer.json` and Dev Container Features, built for CI and for AI-agent sandboxes.**

Dev containers are the default sandbox for Claude Code, Codex, Gemini CLI and Copilot agents, but one line in `devcontainer.json` (`--privileged`, a mounted `docker.sock`, `~/.ssh` or `~/.claude` bind mount, `--network=host`) turns that sandbox into a door to your laptop. `devcontainerguard` catches those lines before they are merged.

Given this `.devcontainer/devcontainer.json`:

```jsonc
{
  "image": "mcr.microsoft.com/devcontainers/javascript-node:latest",
  "runArgs": ["--network=host"],
  "mounts": [
    "source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind",
    "source=${localEnv:HOME}/.claude,target=/home/node/.claude,type=bind"
  ],
  "containerEnv": { "ANTHROPIC_API_KEY": "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxx" },
  "postAttachCommand": "claude --dangerously-skip-permissions"
}
```

```console
$ devcontainerguard
.devcontainer/devcontainer.json:1:1           info     DCG016  devcontainer.json has no 'name'; set one so the container is identifiable in editors and Codespaces
.devcontainer/devcontainer.json:2:12          warning  DCG007  image 'mcr.microsoft.com/devcontainers/javascript-node:latest' uses the 'latest' tag; pin a version tag or @sha256 digest
.devcontainer/devcontainer.json:3:15          error    DCG004  --network=host shares the host network namespace
.devcontainer/devcontainer.json:5:5           error    DCG002  host container socket /var/run/docker.sock is mounted; anything in the container (including an AI agent) gets root on the host
.devcontainer/devcontainer.json:6:5           warning  DCG018  host credentials ${localEnv:HOME}/.claude are bind-mounted; use a per-container named volume or a scoped token instead
.devcontainer/devcontainer.json:8:42          error    DCG009  containerEnv 'ANTHROPIC_API_KEY' has a literal secret-looking value; pass it with ${localEnv:ANTHROPIC_API_KEY} or a secrets manager instead
.devcontainer/devcontainer.json:9:24          error    DCG017  AI agent approvals are disabled ('--dangerously-skip-permissions') while the container has host access (DCG002, DCG004); a prompt injection can reach the host. Remove the host access or keep approvals on

7 problem(s) in 1 file(s): 4 error, 2 warning, 1 info
```

## Why devcontainerguard?

- **Security rules, not just schema.** JSON Schema and `devcontainer read-configuration` tell you whether the file is valid; they do not tell you it mounts your home directory. 20 rules with stable IDs ([`DCG001`…`DCG020`](docs/rules.md)).
- **AI-agent aware.** Flags `--dangerously-skip-permissions` / `--yolo` *only when combined with host access* (DCG017), host agent-credential mounts (DCG018) and firewall capabilities (DCG019). The [Claude Code reference devcontainer](https://github.com/anthropics/claude-code/tree/main/.devcontainer) passes with a single info note.
- **Real JSONC.** Comments, trailing commas, exact `line:column` for every finding.
- **One self-contained Rust binary.** No Node, Python or Docker needed. Lints a whole monorepo in milliseconds.
- **CI-native output.** Human, JSON, **SARIF** (GitHub code scanning) and **GitHub annotations**; a ready-made [GitHub Action](#github-actions).
- **Predictable exit codes.** `0` clean, `1` findings at or above `--fail-on`, `2` usage or parse error.

## Install

**Prebuilt binaries** (Linux x86_64/arm64, macOS x86_64/arm64, Windows x86_64) are on the [releases page](https://github.com/hamarshehmhmd/devcontainerguard/releases):

```sh
VERSION=v0.1.0
TARGET=x86_64-unknown-linux-gnu   # or aarch64-unknown-linux-gnu, x86_64-apple-darwin, aarch64-apple-darwin
curl -sSL "https://github.com/hamarshehmhmd/devcontainerguard/releases/download/$VERSION/devcontainerguard-$VERSION-$TARGET.tar.gz" | tar xz
sudo mv devcontainerguard-$VERSION-$TARGET/devcontainerguard /usr/local/bin/
```

**From source** (Rust 1.88+):

```sh
cargo install --git https://github.com/hamarshehmhmd/devcontainerguard
```

## Quickstart

```sh
devcontainerguard                                  # recursively lint ./ (devcontainer.json, .devcontainer.json, devcontainer-feature.json)
devcontainerguard .devcontainer/devcontainer.json  # specific files or directories
devcontainerguard -f sarif > results.sarif         # SARIF for code scanning
devcontainerguard -f github                        # ::error file=...,line=...,col=... annotations
devcontainerguard --fail-on error                  # only fail on errors (default: warning)
devcontainerguard --ignore DCG016                  # disable a rule
devcontainerguard --ignore-path 'examples/**'      # skip files
devcontainerguard --list-rules
```

Directories are searched recursively (skipping `.git`, `node_modules`, `target`, …), so `.devcontainer/*/devcontainer.json` multi-config setups and `src/*/devcontainer-feature.json` Feature repos are picked up automatically.

## Rules

| ID | Name | Severity | What it catches |
|----|------|----------|-----------------|
| [DCG001](docs/rules.md#dcg001) | privileged | error | `privileged: true` / `--privileged` |
| [DCG002](docs/rules.md#dcg002) | docker-socket | error | host `docker.sock` / `podman.sock` mount |
| [DCG003](docs/rules.md#dcg003) | sensitive-host-mount | error | bind mount of `/`, `/etc`, home dir, `~/.ssh`, `~/.aws`, `~/.kube`… |
| [DCG004](docs/rules.md#dcg004) | host-namespace | error | `--network/--pid/--ipc/--uts/--userns=host` |
| [DCG005](docs/rules.md#dcg005) | dangerous-capability | error | `capAdd` ALL, SYS_ADMIN, SYS_MODULE, BPF… |
| [DCG006](docs/rules.md#dcg006) | unconfined-security-profile | error | `seccomp`/`apparmor` unconfined, `label=disable` |
| [DCG007](docs/rules.md#dcg007) | unpinned-image | warning | image `:latest` or untagged |
| [DCG008](docs/rules.md#dcg008) | unpinned-feature | warning | feature without version / `latest` |
| [DCG009](docs/rules.md#dcg009) | plaintext-secret | error | literal secrets in `containerEnv`, `remoteEnv`, `build.args`, `--env` |
| [DCG010](docs/rules.md#dcg010) | root-user | warning | `remoteUser`/`containerUser` root |
| [DCG011](docs/rules.md#dcg011) | pipe-to-shell | warning | `curl … \| sh` in lifecycle commands |
| [DCG012](docs/rules.md#dcg012) | deprecated-property | warning | `extensions`, `settings`, `dockerFile`, `context`, `devPort` |
| [DCG013](docs/rules.md#dcg013) | conflicting-sources | error | `image` + `build` / `dockerComposeFile` together |
| [DCG014](docs/rules.md#dcg014) | port-exposed | warning | `appPort`, `-p` without 127.0.0.1, `-P` |
| [DCG015](docs/rules.md#dcg015) | initialize-command-on-host | warning | `initializeCommand` (runs on the host) |
| [DCG016](docs/rules.md#dcg016) | missing-metadata | info | no `name` (or Feature `id`/`version`) |
| [DCG017](docs/rules.md#dcg017) | agent-autonomy-with-host-access | error | `--dangerously-skip-permissions` / `--yolo` **plus** host access |
| [DCG018](docs/rules.md#dcg018) | agent-credentials-mount | warning | host `~/.claude`, `~/.codex`, `~/.config/gh`, `~/.npmrc` mounts |
| [DCG019](docs/rules.md#dcg019) | network-capability | info | `NET_ADMIN` / `NET_RAW` (firewall check) |
| [DCG020](docs/rules.md#dcg020) | host-access-feature | warning | docker-in-docker / docker-outside-of-docker Features |

Full rationale, bad/good examples and fixes: **[docs/rules.md](docs/rules.md)**.

## Configuration

Put a `.devcontainerguard.yaml` in the directory you run from (or pass `--config`):

```yaml
ignore: [DCG016]            # disable rules
fail_on: warning            # info | warning | error | never
severity:
  DCG015: error             # per-rule severity override
ignore_paths:
  - "examples/**"           # globs of files to skip
```

### Inline ignores

```jsonc
{
  // devcontainerguard-ignore DCG002 -- e2e tests need the host daemon
  "mounts": [
    "source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"
  ],
  "remoteUser": "root" // devcontainerguard-ignore DCG010
}
```

A comment on its own line applies to the whole property that follows it; a trailing comment applies to its line. A bare `// devcontainerguard-ignore` silences every rule there, and `// devcontainerguard-ignore-file` skips the file.

## GitHub Actions

```yaml
name: devcontainer-lint
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  devcontainerguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hamarshehmhmd/devcontainerguard@v0.1.0
        with:
          fail-on: error
          sarif-file: devcontainerguard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: devcontainerguard.sarif
```

Inputs: `paths` (space-separated; default: repository root), `format` (default `github`), `fail-on` (default `warning`), `version` (default `latest`), `sarif-file` (optional). Works on Linux, macOS and Windows runners.

## Related projects

- [devcontainers/cli](https://github.com/devcontainers/cli) is the reference implementation; it validates and builds configs but has no security rules.
- [decolint](https://github.com/bare-devcontainer/decolint) is a broader Go linter for Dev Container definitions, Features and Templates (correctness, security, reproducibility). If you want hardening-baseline checks such as `cap-drop ALL` or digest pinning everywhere, try it too.
- devcontainerguard focuses on **high-signal host-exposure and AI-agent sandbox risks** (DCG017–DCG019), with a low-noise default rule set meant to be safe to turn on as a blocking CI check.

## Contributing

New rules are very welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) and the [good first issues](https://github.com/hamarshehmhmd/devcontainerguard/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22). Please report vulnerabilities privately ([SECURITY.md](SECURITY.md)).

## License

[MIT](LICENSE) © Mohammad Hamarsheh
