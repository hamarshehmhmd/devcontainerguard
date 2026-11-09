# Rules

Every rule has a stable ID that is never reused. Severities can be overridden in `.devcontainerguard.yaml`.

| ID | Name | Severity |
|----|------|----------|
| [DCG001](#dcg001) | privileged | error |
| [DCG002](#dcg002) | docker-socket | error |
| [DCG003](#dcg003) | sensitive-host-mount | error |
| [DCG004](#dcg004) | host-namespace | error |
| [DCG005](#dcg005) | dangerous-capability | error |
| [DCG006](#dcg006) | unconfined-security-profile | error |
| [DCG007](#dcg007) | unpinned-image | warning |
| [DCG008](#dcg008) | unpinned-feature | warning |
| [DCG009](#dcg009) | plaintext-secret | error |
| [DCG010](#dcg010) | root-user | warning |
| [DCG011](#dcg011) | pipe-to-shell | warning |
| [DCG012](#dcg012) | deprecated-property | warning |
| [DCG013](#dcg013) | conflicting-sources | error |
| [DCG014](#dcg014) | port-exposed | warning |
| [DCG015](#dcg015) | initialize-command-on-host | warning |
| [DCG016](#dcg016) | missing-metadata | info |
| [DCG017](#dcg017) | agent-autonomy-with-host-access | error |
| [DCG018](#dcg018) | agent-credentials-mount | warning |
| [DCG019](#dcg019) | network-capability | info |
| [DCG020](#dcg020) | host-access-feature | warning |

<a id="dcg001"></a>
## DCG001 `privileged` (error)

**Flags:** `"privileged": true` or `--privileged` in `runArgs`.

**Why:** A privileged container can access every host device, load kernel modules and trivially escape to the host. In a devcontainer that runs third-party code or an AI agent, that is full host compromise.

**Bad:**

```jsonc
"privileged": true
```

**Better:**

```jsonc
"capAdd": ["SYS_PTRACE"]  // only what you need
```

Suppress: `// devcontainerguard-ignore DCG001` on or above the line.

<a id="dcg002"></a>
## DCG002 `docker-socket` (error)

**Flags:** Bind mount of `docker.sock`, `podman.sock` or `containerd.sock` (in `mounts`, `workspaceMount` or `runArgs -v/--mount`).

**Why:** Access to the host container daemon is root on the host: `docker run -v /:/host --privileged ...`.

**Bad:**

```jsonc
"mounts": ["source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"]
```

**Better:**

```jsonc
"features": { "ghcr.io/devcontainers/features/docker-in-docker:2": {} }  // isolated daemon (still privileged, see DCG020)
```

Suppress: `// devcontainerguard-ignore DCG002` on or above the line.

<a id="dcg003"></a>
## DCG003 `sensitive-host-mount` (error)

**Flags:** Bind mount of `/`, `/etc`, `/proc`, `/sys`, `/dev`, `/run`, `/var/lib/docker`, ..., the whole home directory (`${localEnv:HOME}`, `~`, `/home/x`, `/Users/x`), or credential directories (`.ssh`, `.aws`, `.kube`, `.gnupg`, `.docker`, `.azure`, `.config`, `.config/gcloud`).

**Why:** Anything in the container can read or overwrite these. SSH keys and cloud credentials are the first thing malware and prompt-injected agents look for.

**Bad:**

```jsonc
"source=${localEnv:HOME}/.ssh,target=/home/vscode/.ssh,type=bind"
```

**Fix:** Use SSH agent forwarding (automatic in VS Code / devcontainers CLI) or short-lived credentials.

Suppress: `// devcontainerguard-ignore DCG003` on or above the line.

<a id="dcg004"></a>
## DCG004 `host-namespace` (error)

**Flags:** `--network=host`, `--net host`, `--pid=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host` in `runArgs`.

**Why:** Sharing host namespaces removes isolation: host network exposes every localhost service on the host to the container; host PID allows signalling/inspecting host processes.

**Bad:**

```jsonc
"runArgs": ["--network=host"]
```

**Better:**

```jsonc
"forwardPorts": [3000]
```

Suppress: `// devcontainerguard-ignore DCG004` on or above the line.

<a id="dcg005"></a>
## DCG005 `dangerous-capability` (error)

**Flags:** `capAdd` / `--cap-add` with `ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `SYS_BOOT`, `SYS_TIME`, `DAC_READ_SEARCH` or `BPF`.

**Why:** These capabilities are known container escape or host-tampering primitives (mount, load kernel modules, raw I/O, read arbitrary files via handles).

**Bad:**

```jsonc
"capAdd": ["SYS_ADMIN"]
```

**Fix:** Remove it, or use a narrower capability.

Suppress: `// devcontainerguard-ignore DCG005` on or above the line.

<a id="dcg006"></a>
## DCG006 `unconfined-security-profile` (error)

**Flags:** `securityOpt` / `--security-opt` with `seccomp=unconfined`, `apparmor=unconfined`, `label=disable` or `systempaths=unconfined` (`:` or `=` form).

**Why:** Disables the kernel syscall filter / MAC profile that blocks most escape techniques.

**Bad:**

```jsonc
"securityOpt": ["seccomp=unconfined"]
```

**Fix:** Remove it; for debuggers, `SYS_PTRACE` alone is usually enough.

Suppress: `// devcontainerguard-ignore DCG006` on or above the line.

<a id="dcg007"></a>
## DCG007 `unpinned-image` (warning)

**Flags:** `image` with no tag, an empty tag, or `:latest`. Digests (`@sha256:`) and `${...}` variables are accepted.

**Why:** Builds become non-reproducible and a compromised or broken upstream `latest` lands silently.

**Bad:**

```jsonc
"image": "mcr.microsoft.com/devcontainers/base:latest"
```

**Better:**

```jsonc
"image": "mcr.microsoft.com/devcontainers/base:1-bookworm"
```

Suppress: `// devcontainerguard-ignore DCG007` on or above the line.

<a id="dcg008"></a>
## DCG008 `unpinned-feature` (warning)

**Flags:** A key in `features` (or `dependsOn` in a Feature) with no version, `:latest`, or a legacy short ID (`node`). Local (`./x`) and tarball URLs are skipped.

**Why:** Features run as root at build time; an unpinned reference executes whatever was published last.

**Bad:**

```jsonc
"ghcr.io/devcontainers/features/node": {}
```

**Better:**

```jsonc
"ghcr.io/devcontainers/features/node:1": {}
```

Suppress: `// devcontainerguard-ignore DCG008` on or above the line.

<a id="dcg009"></a>
## DCG009 `plaintext-secret` (error)

**Flags:** A literal value in `containerEnv`, `remoteEnv`, `build.args` or `runArgs -e/--env` whose name looks secret (`*_PASSWORD`, `*_TOKEN`, `*_SECRET`, `*_API_KEY`, `*_ACCESS_KEY`, `*_PRIVATE_KEY`, `*_CREDENTIALS`; names ending in `_URL`, `_FILE`, `_PATH`, `_HOST`, ... are exempt) or whose value matches a known token format (GitHub, Anthropic, OpenAI, AWS, Slack, GitLab, Google, npm). `${localEnv:X}` style references are fine. The value itself is never printed.

**Why:** devcontainer.json is committed; secrets in it are leaked to everyone with repo access and baked into image layers (build args).

**Bad:**

```jsonc
"containerEnv": { "ANTHROPIC_API_KEY": "sk-ant-..." }
```

**Better:**

```jsonc
"containerEnv": { "ANTHROPIC_API_KEY": "${localEnv:ANTHROPIC_API_KEY}" }
```

Suppress: `// devcontainerguard-ignore DCG009` on or above the line.

<a id="dcg010"></a>
## DCG010 `root-user` (warning)

**Flags:** `remoteUser` / `containerUser` set to `root`/`0`, or `runArgs -u/--user root`.

**Why:** Tools, extensions and agents then run as root in the container, so any container escape or writable host mount is root-owned.

**Bad:**

```jsonc
"remoteUser": "root"
```

**Better:**

```jsonc
"remoteUser": "vscode"
```

Suppress: `// devcontainerguard-ignore DCG010` on or above the line.

<a id="dcg011"></a>
## DCG011 `pipe-to-shell` (warning)

**Flags:** A lifecycle command (`initializeCommand`, `onCreateCommand`, `updateContentCommand`, `postCreateCommand`, `postStartCommand`, `postAttachCommand`; string, array or object form) that runs `curl|sh`, `wget|bash`, `sh -c "$(curl ...)"`, `bash <(curl ...)` or `iwr ... | iex`.

**Why:** Unverified remote code runs every time the container is created; a compromised URL owns every contributor's environment.

**Bad:**

```jsonc
"postCreateCommand": "curl -fsSL https://x.sh | bash"
```

**Fix:** Use a Feature, or download, verify a checksum, then execute.

Suppress: `// devcontainerguard-ignore DCG011` on or above the line.

<a id="dcg012"></a>
## DCG012 `deprecated-property` (warning)

**Flags:** Top-level `extensions`, `settings` (use `customizations.vscode`), `dockerFile`, `context` (use `build.dockerfile`/`build.context`), `devPort` (use `forwardPorts`).

**Why:** Deprecated properties are ignored by some tools (Codespaces, devcontainers CLI, other editors).

**Bad:**

```jsonc
"extensions": ["ms-python.python"]
```

**Better:**

```jsonc
"customizations": { "vscode": { "extensions": ["ms-python.python"] } }
```

Suppress: `// devcontainerguard-ignore DCG012` on or above the line.

<a id="dcg013"></a>
## DCG013 `conflicting-sources` (error)

**Flags:** More than one of `image`, `build`/`dockerFile` and `dockerComposeFile`.

**Why:** Only one is used; the others are silently ignored, so the config does not do what it says (often an old `image` overrides a hardened Dockerfile, or vice versa).

**Bad:**

```jsonc
"image": "node:22", "build": { "dockerfile": "Dockerfile" }
```

**Fix:** Keep exactly one.

Suppress: `// devcontainerguard-ignore DCG013` on or above the line.

<a id="dcg014"></a>
## DCG014 `port-exposed` (warning)

**Flags:** `appPort` (any value), `runArgs -P/--publish-all`, or `-p/--publish` not bound to `127.0.0.1`/`localhost`/`[::1]`.

**Why:** Published ports listen on all host interfaces, exposing dev servers (often without auth) to the LAN or café Wi-Fi. `forwardPorts` stays on localhost.

**Bad:**

```jsonc
"appPort": [3000]
```

**Better:**

```jsonc
"forwardPorts": [3000]
```

Suppress: `// devcontainerguard-ignore DCG014` on or above the line.

<a id="dcg015"></a>
## DCG015 `initialize-command-on-host` (warning)

**Flags:** `initializeCommand` is set.

**Why:** It runs **on the host** with your user's permissions when someone opens the repo, before any container isolation. Malicious repos use it as an RCE vector; reviewers should see it flagged.

**Bad:**

```jsonc
"initializeCommand": "./scripts/setup.sh"
```

**Fix:** Move work into `onCreateCommand`/`postCreateCommand`, or ignore inline after review.

Suppress: `// devcontainerguard-ignore DCG015` on or above the line.

<a id="dcg016"></a>
## DCG016 `missing-metadata` (info)

**Flags:** `devcontainer.json` without `name`; `devcontainer-feature.json` without `id` or `version`.

**Why:** Unnamed containers are hard to identify in editors/Codespaces; Features without id/version cannot be published.

**Bad:**

```jsonc
{ "image": "..." }
```

**Better:**

```jsonc
{ "name": "API", "image": "..." }
```

Suppress: `// devcontainerguard-ignore DCG016` on or above the line.

<a id="dcg017"></a>
## DCG017 `agent-autonomy-with-host-access` (error)

**Flags:** Any string contains an AI-agent approval bypass (`--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `danger-full-access`, `--yolo`, `--approval-mode yolo`, `--trust-all-tools`, `--allow-all-tools`) **and** the same file has host access (any of DCG001–DCG006 or DCG020).

**Why:** Running Claude Code / Codex / Gemini CLI without approvals is only reasonable inside a sandbox. With host access, a single prompt injection (README, issue, dependency) escapes to your machine.

**Bad:**

```jsonc
"runArgs": ["--network=host"], "postAttachCommand": "claude --dangerously-skip-permissions"
```

**Fix:** Drop the host access (see the Claude Code reference devcontainer: named volumes, egress firewall) or keep approvals on.

Suppress: `// devcontainerguard-ignore DCG017` on or above the line.

<a id="dcg018"></a>
## DCG018 `agent-credentials-mount` (warning)

**Flags:** Bind mount of host `~/.claude`, `~/.claude.json`, `~/.codex`, `~/.gemini`, `~/.cursor`, `~/.aider`, `~/.config/gh`, `~/.config/github-copilot`, `~/.git-credentials`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials*`.

**Why:** Long-lived OAuth tokens become readable (and exfiltratable) by anything in the container, including the agent itself.

**Bad:**

```jsonc
"source=${localEnv:HOME}/.claude,target=/home/node/.claude,type=bind"
```

**Better:**

```jsonc
"source=claude-config-${devcontainerId},target=/home/node/.claude,type=volume"
```

Suppress: `// devcontainerguard-ignore DCG018` on or above the line.

<a id="dcg019"></a>
## DCG019 `network-capability` (info)

**Flags:** `NET_ADMIN` or `NET_RAW` added.

**Why:** Needed for in-container egress firewalls (the Claude Code reference devcontainer uses them), but if the agent/user can still use them (e.g. passwordless sudo), they can flush the firewall or sniff traffic.

**Bad:**

```jsonc
"runArgs": ["--cap-add=NET_ADMIN"]
```

**Fix:** Keep it, but restrict sudo to the firewall script only.

Suppress: `// devcontainerguard-ignore DCG019` on or above the line.

<a id="dcg020"></a>
## DCG020 `host-access-feature` (warning)

**Flags:** Feature `.../docker-in-docker` (forces privileged) or `.../docker-outside-of-docker` / `docker-from-docker` (mounts the host socket).

**Why:** These Features silently add the same risk as DCG001/DCG002.

**Bad:**

```jsonc
"ghcr.io/devcontainers/features/docker-outside-of-docker:1": {}
```

**Fix:** Prefer docker-in-docker over outside-of-docker if you need Docker, and never combine either with agent autonomy.

Suppress: `// devcontainerguard-ignore DCG020` on or above the line.
