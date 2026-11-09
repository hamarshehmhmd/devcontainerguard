# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-09

### Added
- 20 rules (DCG001–DCG020): privileged mode, host container sockets, sensitive host and credential mounts, host namespaces, escape-grade capabilities, unconfined seccomp/AppArmor, unpinned images and Features, plaintext secrets, root users, `curl | sh` lifecycle commands, deprecated properties, conflicting container sources, exposed ports, `initializeCommand` on the host, missing metadata, and AI-agent sandbox rules (approval bypass with host access, agent credential mounts, firewall capabilities, host-access Features).
- JSONC parser with comments, trailing commas and line/column positions.
- Lints `devcontainer.json`, `.devcontainer.json` and `devcontainer-feature.json`; recursive directory discovery.
- Output formats: human, JSON, SARIF 2.1.0, GitHub annotations.
- `.devcontainerguard.yaml` config (ignore, fail_on, severity, ignore_paths) and inline `// devcontainerguard-ignore` comments.
- CI exit codes (0/1/2), composite GitHub Action, prebuilt binaries for Linux, macOS and Windows.

[0.1.0]: https://github.com/hamarshehmhmd/devcontainerguard/releases/tag/v0.1.0
