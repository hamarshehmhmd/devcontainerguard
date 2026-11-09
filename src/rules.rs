//! Rule catalogue and checks.

use crate::jsonc::{Node, Pos, Value};
use crate::{Finding, Kind, Severity};
use regex::Regex;
use std::sync::LazyLock;

/// Static metadata for a rule.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    pub description: &'static str,
}

macro_rules! rules {
    ($( $id:literal, $name:literal, $sev:ident, $desc:literal; )*) => {
        pub const RULES: &[Rule] = &[ $( Rule { id: $id, name: $name, severity: Severity::$sev, description: $desc } ),* ];
    };
}

rules! {
    "DCG001", "privileged", Error, "Container runs privileged (privileged: true or --privileged)";
    "DCG002", "docker-socket", Error, "Host Docker/Podman/containerd socket is mounted into the container";
    "DCG003", "sensitive-host-mount", Error, "Host root, system directory, home directory or credential directory (.ssh, .aws, .kube, ...) is bind-mounted";
    "DCG004", "host-namespace", Error, "Container shares a host namespace (--network/--pid/--ipc/--uts/--userns/--cgroupns=host)";
    "DCG005", "dangerous-capability", Error, "Capability that allows host escape is added (ALL, SYS_ADMIN, SYS_MODULE, SYS_RAWIO, BPF, ...)";
    "DCG006", "unconfined-security-profile", Error, "seccomp/AppArmor/SELinux confinement is disabled";
    "DCG007", "unpinned-image", Warning, "Image uses the latest tag or no tag/digest";
    "DCG008", "unpinned-feature", Warning, "Feature reference has no version or uses latest";
    "DCG009", "plaintext-secret", Error, "Secret-looking literal value in containerEnv, remoteEnv, build.args or runArgs --env";
    "DCG010", "root-user", Warning, "remoteUser/containerUser (or --user) is root";
    "DCG011", "pipe-to-shell", Warning, "Lifecycle command pipes a remote download straight into a shell (curl ... | sh)";
    "DCG012", "deprecated-property", Warning, "Deprecated property (extensions, settings, dockerFile, context, devPort)";
    "DCG013", "conflicting-sources", Error, "More than one of image, build/dockerFile and dockerComposeFile is set";
    "DCG014", "port-exposed", Warning, "appPort or runArgs --publish exposes a port on all host interfaces";
    "DCG015", "initialize-command-on-host", Warning, "initializeCommand runs on the host machine, outside the container";
    "DCG016", "missing-metadata", Info, "Missing name (devcontainer.json) or id/version (devcontainer-feature.json)";
    "DCG017", "agent-autonomy-with-host-access", Error, "AI agent approvals are disabled (--dangerously-skip-permissions, --yolo, ...) in a container that also has host access";
    "DCG018", "agent-credentials-mount", Warning, "Host AI-agent or package-registry credentials (~/.claude, ~/.codex, ~/.config/gh, ~/.npmrc, ...) are bind-mounted";
    "DCG019", "network-capability", Info, "NET_ADMIN/NET_RAW capability added; fine for an egress firewall, but make sure the agent cannot use it";
    "DCG020", "host-access-feature", Warning, "Feature grants host-level access (docker-in-docker runs privileged, docker-outside-of-docker mounts the host socket)";
}

/// Look up a rule by ID.
pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

const LIFECYCLE: &[&str] = &[
    "initializeCommand",
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
];

/// IDs that represent direct host access, used by DCG017.
const HOST_ACCESS: &[&str] = &[
    "DCG001", "DCG002", "DCG003", "DCG004", "DCG005", "DCG006", "DCG020",
];

struct Ctx {
    out: Vec<Finding>,
}

impl Ctx {
    fn add(&mut self, id: &'static str, pos: Pos, message: String) {
        let r = rule(id).expect("known rule id");
        self.out.push(Finding {
            rule: r.id,
            severity: r.severity,
            message,
            line: pos.line,
            column: pos.col,
        });
    }
}

/// A host mount extracted from mounts, workspaceMount or runArgs.
struct Mount<'a> {
    node: &'a Node,
    source: String,
    kind: Option<String>,
}

/// A runArgs flag with its (optional) value.
struct RunArg<'a> {
    node: &'a Node,
    flag: String,
    value: Option<String>,
}

const VALUE_FLAGS: &[&str] = &[
    "-v",
    "--volume",
    "--mount",
    "--network",
    "--net",
    "--pid",
    "--ipc",
    "--uts",
    "--userns",
    "--cgroupns",
    "--cap-add",
    "--security-opt",
    "-p",
    "--publish",
    "-e",
    "--env",
    "-u",
    "--user",
];

fn run_args(doc: &Node) -> Vec<RunArg<'_>> {
    let Some(items) = doc.get("runArgs").and_then(Node::as_array) else {
        return vec![];
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < items.len() {
        let node = &items[i];
        i += 1;
        let Some(s) = node.as_str() else { continue };
        let s = s.trim();
        if let Some((flag, value)) = s
            .split_once(char::is_whitespace)
            .filter(|(f, _)| VALUE_FLAGS.contains(f))
        {
            out.push(RunArg {
                node,
                flag: flag.to_string(),
                value: Some(value.trim().to_string()),
            });
        } else if let Some((flag, value)) = s.split_once('=').filter(|(f, _)| f.starts_with('-')) {
            out.push(RunArg {
                node,
                flag: flag.to_string(),
                value: Some(value.to_string()),
            });
        } else if VALUE_FLAGS.contains(&s) {
            let value = items.get(i).and_then(Node::as_str).map(str::to_string);
            if value.is_some() {
                i += 1;
            }
            out.push(RunArg {
                node,
                flag: s.to_string(),
                value,
            });
        } else {
            out.push(RunArg {
                node,
                flag: s.to_string(),
                value: None,
            });
        }
    }
    out
}

fn parse_mount_kv(s: &str) -> (String, Option<String>) {
    let mut source = String::new();
    let mut kind = None;
    for part in s.split(',') {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        match k.trim() {
            "source" | "src" => source = v.trim().to_string(),
            "type" => kind = Some(v.trim().to_lowercase()),
            _ => {}
        }
    }
    (source, kind)
}

/// `-v SRC:DST[:opts]`. Named volumes are reported with kind `volume`.
fn parse_volume_arg(s: &str) -> (String, Option<String>) {
    let s = s.trim();
    // Windows drive letter, e.g. C:\Users\me:/home/me
    let split_at = if s.len() > 2 && s.as_bytes()[1] == b':' {
        s[2..].find(':').map(|i| i + 2)
    } else {
        s.find(':')
    };
    let source = match split_at {
        Some(i) => &s[..i],
        None => s,
    };
    let looks_like_path = source.starts_with(['/', '.', '~', '$', '\\'])
        || source.contains(":\\")
        || source.contains(":/");
    let kind = if looks_like_path { "bind" } else { "volume" };
    (source.to_string(), Some(kind.to_string()))
}

fn mounts(doc: &Node) -> Vec<Mount<'_>> {
    let mut out = Vec::new();
    if let Some(items) = doc.get("mounts").and_then(Node::as_array) {
        for node in items {
            match &node.value {
                Value::String(s) => {
                    let (source, kind) = parse_mount_kv(s);
                    out.push(Mount { node, source, kind });
                }
                Value::Object(_) => {
                    let source = node
                        .get("source")
                        .and_then(Node::as_str)
                        .unwrap_or("")
                        .to_string();
                    let kind = node
                        .get("type")
                        .and_then(Node::as_str)
                        .map(str::to_lowercase);
                    out.push(Mount { node, source, kind });
                }
                _ => {}
            }
        }
    }
    if let Some(node) = doc.get("workspaceMount")
        && let Some(s) = node.as_str()
    {
        let (source, kind) = parse_mount_kv(s);
        out.push(Mount { node, source, kind });
    }
    for a in run_args(doc) {
        let Some(v) = &a.value else { continue };
        let (source, kind) = match a.flag.as_str() {
            "--mount" => parse_mount_kv(v),
            "-v" | "--volume" => parse_volume_arg(v),
            _ => continue,
        };
        out.push(Mount {
            node: a.node,
            source,
            kind,
        });
    }
    out
}

static HOME_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:(?:\$\{(?:localEnv|env):(?:HOME|USERPROFILE)(?::[^}]*)?\})+|~|\$HOME|\$\{HOME\}|/home/[^/]+|/Users/[^/]+|/root|[A-Za-z]:/Users/[^/]+)",
    )
    .unwrap()
});

const SYSTEM_PATHS: &[&str] = &[
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/run",
    "/var/run",
    "/var/lib/docker",
    "/usr",
    "/lib",
    "/bin",
    "/sbin",
    "C:",
    "C:/",
];
const CRED_DIRS: &[&str] = &[
    ".ssh",
    ".aws",
    ".kube",
    ".gnupg",
    ".docker",
    ".azure",
    ".password-store",
    ".oci",
];
const AGENT_CREDS: &[&str] = &[
    ".claude",
    ".claude.json",
    ".codex",
    ".gemini",
    ".cursor",
    ".aider",
    ".git-credentials",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".yarnrc.yml",
];

enum HostPath {
    Sensitive(String),
    AgentCreds(String),
}

fn classify_source(raw: &str) -> Option<HostPath> {
    let norm = raw.replace('\\', "/");
    let norm = norm.trim();
    let trimmed = if norm.len() > 1 {
        norm.trim_end_matches('/')
    } else {
        norm
    };
    if SYSTEM_PATHS.contains(&trimmed) {
        return Some(HostPath::Sensitive(format!("host path {raw}")));
    }
    let m = HOME_PREFIX.find(trimmed)?;
    let rest = trimmed[m.end()..].trim_start_matches('/');
    if rest.is_empty() {
        return Some(HostPath::Sensitive(format!("host home directory {raw}")));
    }
    let first = rest.split('/').next().unwrap_or("");
    if CRED_DIRS.contains(&first) || rest == ".config" || rest.starts_with(".config/gcloud") {
        return Some(HostPath::Sensitive(format!("host credential path {raw}")));
    }
    if AGENT_CREDS.contains(&first)
        || rest.starts_with(".config/gh")
        || rest.starts_with(".config/claude")
        || rest.starts_with(".config/github-copilot")
        || rest.starts_with(".cargo/credentials")
    {
        return Some(HostPath::AgentCreds(raw.to_string()));
    }
    None
}

fn truthy(n: &Node) -> bool {
    n.as_bool() == Some(true) || n.as_str().is_some_and(|s| s.eq_ignore_ascii_case("true"))
}

fn norm_cap(s: &str) -> String {
    let up = s.trim().to_uppercase();
    up.strip_prefix("CAP_").unwrap_or(&up).to_string()
}

const ESCAPE_CAPS: &[&str] = &[
    "ALL",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_BOOT",
    "DAC_READ_SEARCH",
    "BPF",
    "SYS_TIME",
];

fn check_cap(ctx: &mut Ctx, node: &Node, cap: &str) {
    let c = norm_cap(cap);
    if ESCAPE_CAPS.contains(&c.as_str()) {
        ctx.add(
            "DCG005",
            node.pos,
            format!("capability {c} is added; it allows escaping to or tampering with the host"),
        );
    } else if c == "NET_ADMIN" || c == "NET_RAW" {
        ctx.add(
            "DCG019",
            node.pos,
            format!(
                "capability {c} is added; if it is for an egress firewall, drop it (or sudo) before the agent/user session starts"
            ),
        );
    }
}

fn check_security_opt(ctx: &mut Ctx, node: &Node, opt: &str) {
    let o = opt.trim().to_lowercase().replace(':', "=");
    if matches!(
        o.as_str(),
        "seccomp=unconfined" | "apparmor=unconfined" | "label=disable" | "systempaths=unconfined"
    ) {
        ctx.add(
            "DCG006",
            node.pos,
            format!(
                "security option '{}' disables kernel confinement",
                opt.trim()
            ),
        );
    }
}

/// Is the value an interpolation/empty rather than a literal?
fn is_reference(v: &str) -> bool {
    static REF: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s*(\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*)\s*$").unwrap());
    v.trim().is_empty() || REF.is_match(v)
}

static SECRET_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|_)(password|passwd|pwd|secret|token|api_?key|access_?key|private_?key|credentials?|client_?secret)($|_)").unwrap()
});
static SECRET_NAME_EXEMPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)_(url|uri|path|file|dir|host|endpoint|name|user|username|id)$").unwrap()
});
static SECRET_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|gh[ousr]_[A-Za-z0-9]{30,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-(proj-)?[A-Za-z0-9_-]{32,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20}|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{36})").unwrap()
});

fn check_secret(ctx: &mut Ctx, node: &Node, where_: &str, name: &str, value: &str) {
    if is_reference(value) {
        return;
    }
    let by_name = SECRET_NAME.is_match(name) && !SECRET_NAME_EXEMPT.is_match(name);
    if by_name || SECRET_VALUE.is_match(value) {
        ctx.add(
            "DCG009",
            node.pos,
            format!(
                "{where_} '{name}' has a literal secret-looking value; pass it with ${{localEnv:{name}}} or a secrets manager instead"
            ),
        );
    }
}

fn check_env_object(ctx: &mut Ctx, obj: Option<&Node>, where_: &str) {
    let Some(members) = obj.and_then(Node::as_object) else {
        return;
    };
    for m in members {
        if let Some(v) = m.value.as_str() {
            check_secret(ctx, &m.value, where_, &m.key, v);
        }
    }
}

/// Image reference without tag/digest or with `latest`.
fn image_unpinned(image: &str) -> Option<&'static str> {
    if image.contains("${") || image.contains('@') {
        return None;
    }
    let last = image.rsplit('/').next().unwrap_or(image);
    match last.split_once(':') {
        None => Some("has no tag"),
        Some((_, "latest")) => Some("uses the 'latest' tag"),
        Some((_, "")) => Some("has an empty tag"),
        _ => None,
    }
}

fn feature_unpinned(id: &str) -> Option<&'static str> {
    if id.starts_with("./")
        || id.starts_with("../")
        || id.starts_with('/')
        || id.starts_with("http://")
        || id.starts_with("https://")
        || id.contains('@')
    {
        return None;
    }
    if !id.contains('/') {
        return Some("is a legacy short-form ID with no registry or version");
    }
    image_unpinned(id)
}

/// Collect lifecycle command strings with their node.
fn commands<'a>(doc: &'a Node, out: &mut Vec<(&'static str, &'a Node, String)>) {
    for key in LIFECYCLE {
        let Some(n) = doc.get(key) else { continue };
        collect_command(key, n, out, true);
    }
}

fn collect_command<'a>(
    key: &'static str,
    n: &'a Node,
    out: &mut Vec<(&'static str, &'a Node, String)>,
    allow_object: bool,
) {
    match &n.value {
        Value::String(s) => out.push((key, n, s.clone())),
        Value::Array(items) => {
            let joined = items
                .iter()
                .filter_map(Node::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            out.push((key, n, joined));
        }
        Value::Object(members) if allow_object => {
            for m in members {
                collect_command(key, &m.value, out, false);
            }
        }
        _ => {}
    }
}

static PIPE_SHELL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^|;&]*\|\s*(sudo\s+(-\S+\s+)*)?(env\s+\S+\s+)?(ba|z|da|k|fi)?sh\b|\b(ba|z)?sh\s+(-c\s+)?["']?\$\(\s*(curl|wget)\b|<\(\s*(curl|wget)\b|\|\s*iex\b"#).unwrap()
});

static AGENT_YOLO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"--dangerously-skip-permissions|--allow-dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|--approval-mode[= ]+yolo|danger-full-access|--trust-all-tools|--allow-all-tools").unwrap()
});

/// Run every rule over a parsed document.
pub fn check(doc: &Node, kind: Kind) -> Vec<Finding> {
    let mut ctx = Ctx { out: Vec::new() };
    if doc.as_object().is_none() {
        return ctx.out;
    }
    let args = run_args(doc);

    // DCG001 privileged
    if let Some(n) = doc.get("privileged")
        && truthy(n)
    {
        ctx.add(
            "DCG001",
            n.pos,
            "privileged: true gives the container full access to host devices and kernel; grant specific capabilities instead".into(),
        );
    }
    for a in &args {
        if a.flag == "--privileged" && a.value.as_deref().is_none_or(|v| v != "false") {
            ctx.add(
                "DCG001",
                a.node.pos,
                "runArgs --privileged gives the container full access to host devices and kernel"
                    .into(),
            );
        }
    }

    // DCG002 / DCG003 / DCG018 mounts
    for m in mounts(doc) {
        let lower = m.source.to_lowercase();
        if ["docker.sock", "podman.sock", "containerd.sock"]
            .iter()
            .any(|s| lower.contains(s))
        {
            ctx.add(
                "DCG002",
                m.node.pos,
                format!(
                    "host container socket {} is mounted; anything in the container (including an AI agent) gets root on the host",
                    m.source
                ),
            );
            continue;
        }
        if matches!(m.kind.as_deref(), Some("volume" | "tmpfs" | "npipe")) {
            continue;
        }
        match classify_source(&m.source) {
            Some(HostPath::Sensitive(what)) => ctx.add(
                "DCG003",
                m.node.pos,
                format!("{what} is bind-mounted into the container"),
            ),
            Some(HostPath::AgentCreds(p)) => ctx.add(
                "DCG018",
                m.node.pos,
                format!(
                    "host credentials {p} are bind-mounted; use a per-container named volume or a scoped token instead"
                ),
            ),
            None => {}
        }
    }

    // DCG004 host namespaces
    for a in &args {
        let ns = match a.flag.as_str() {
            "--network" | "--net" => "network",
            "--pid" => "PID",
            "--ipc" => "IPC",
            "--uts" => "UTS",
            "--userns" => "user",
            "--cgroupns" => "cgroup",
            _ => continue,
        };
        if a.value.as_deref().map(str::trim) == Some("host") {
            ctx.add(
                "DCG004",
                a.node.pos,
                format!("{}=host shares the host {ns} namespace", a.flag),
            );
        }
    }

    // DCG005 / DCG019 capabilities
    if let Some(items) = doc.get("capAdd").and_then(Node::as_array) {
        for n in items {
            if let Some(s) = n.as_str() {
                check_cap(&mut ctx, n, s);
            }
        }
    }
    for a in &args {
        if a.flag == "--cap-add"
            && let Some(v) = &a.value
        {
            check_cap(&mut ctx, a.node, v);
        }
    }

    // DCG006 security options
    if let Some(items) = doc.get("securityOpt").and_then(Node::as_array) {
        for n in items {
            if let Some(s) = n.as_str() {
                check_security_opt(&mut ctx, n, s);
            }
        }
    }
    for a in &args {
        if a.flag == "--security-opt"
            && let Some(v) = &a.value
        {
            check_security_opt(&mut ctx, a.node, v);
        }
    }

    // DCG007 image
    if let Some(n) = doc.get("image")
        && let Some(img) = n.as_str()
        && let Some(why) = image_unpinned(img)
    {
        ctx.add(
            "DCG007",
            n.pos,
            format!("image '{img}' {why}; pin a version tag or @sha256 digest"),
        );
    }

    // DCG008 / DCG020 features
    for key in ["features", "dependsOn"] {
        let Some(members) = doc.get(key).and_then(Node::as_object) else {
            continue;
        };
        for m in members {
            let pos = m.key_pos;
            if let Some(why) = feature_unpinned(&m.key) {
                ctx.add(
                    "DCG008",
                    pos,
                    format!(
                        "feature '{}' {why}; pin a major version (e.g. :1) or digest",
                        m.key
                    ),
                );
            }
            let base = m.key.split([':', '@']).next().unwrap_or("");
            if base.ends_with("/docker-in-docker") {
                ctx.add(
                    "DCG020",
                    pos,
                    format!("feature '{}' makes the container run privileged", m.key),
                );
            } else if base.ends_with("/docker-outside-of-docker")
                || base.ends_with("/docker-from-docker")
            {
                ctx.add(
                    "DCG020",
                    pos,
                    format!(
                        "feature '{}' mounts the host Docker socket (root on the host)",
                        m.key
                    ),
                );
            }
        }
    }

    // DCG009 secrets
    check_env_object(&mut ctx, doc.get("containerEnv"), "containerEnv");
    check_env_object(&mut ctx, doc.get("remoteEnv"), "remoteEnv");
    check_env_object(
        &mut ctx,
        doc.get("build").and_then(|b| b.get("args")),
        "build.args",
    );
    for a in &args {
        if matches!(a.flag.as_str(), "-e" | "--env")
            && let Some(v) = &a.value
            && let Some((name, value)) = v.split_once('=')
        {
            check_secret(&mut ctx, a.node, "runArgs --env", name.trim(), value);
        }
    }

    // DCG010 root user
    for key in ["remoteUser", "containerUser"] {
        if let Some(n) = doc.get(key)
            && let Some(u) = n.as_str()
            && is_root(u)
        {
            ctx.add(
                "DCG010",
                n.pos,
                format!(
                    "{key} is '{u}'; use a non-root user (e.g. vscode, node) and sudo when needed"
                ),
            );
        }
    }
    for a in &args {
        if matches!(a.flag.as_str(), "-u" | "--user")
            && let Some(u) = &a.value
            && is_root(u)
        {
            ctx.add(
                "DCG010",
                a.node.pos,
                format!("runArgs {} {u} runs as root", a.flag),
            );
        }
    }

    // DCG011 pipe to shell, DCG015 initializeCommand
    let mut cmds = Vec::new();
    commands(doc, &mut cmds);
    for (key, n, text) in &cmds {
        if PIPE_SHELL.is_match(text) {
            ctx.add(
                "DCG011",
                n.pos,
                format!("{key} pipes a download into a shell; download, verify a checksum, then run (or use a Feature)"),
            );
        }
    }
    if kind == Kind::DevContainer
        && let Some(m) = doc.member("initializeCommand")
    {
        ctx.add(
            "DCG015",
            m.key_pos,
            "initializeCommand runs on the host with your user's permissions before the container starts; keep it minimal and review it like a script you run locally".into(),
        );
    }

    // DCG012 deprecated, DCG013 conflicts, DCG014 ports, DCG016 metadata
    if kind == Kind::DevContainer {
        for (key, hint) in [
            ("extensions", "customizations.vscode.extensions"),
            ("settings", "customizations.vscode.settings"),
            ("dockerFile", "build.dockerfile"),
            ("context", "build.context"),
            ("devPort", "forwardPorts"),
        ] {
            if let Some(m) = doc.member(key) {
                ctx.add(
                    "DCG012",
                    m.key_pos,
                    format!("'{key}' is deprecated; use '{hint}'"),
                );
            }
        }

        let mut sources = Vec::new();
        if doc.member("image").is_some() {
            sources.push("image");
        }
        if doc.member("build").is_some() || doc.member("dockerFile").is_some() {
            sources.push("build");
        }
        if doc.member("dockerComposeFile").is_some() {
            sources.push("dockerComposeFile");
        }
        if sources.len() > 1 {
            let pos = ["image", "build", "dockerFile", "dockerComposeFile"]
                .iter()
                .filter_map(|k| doc.member(k))
                .map(|m| m.key_pos)
                .max()
                .unwrap_or_default();
            ctx.add(
                "DCG013",
                pos,
                if sources.len() == 2 {
                    format!(
                        "{} and {} are both set; only one container source is used, the other is silently ignored",
                        sources[0], sources[1]
                    )
                } else {
                    "image, build and dockerComposeFile are all set; only one container source is used, the rest is silently ignored".into()
                },
            );
        }

        if let Some(m) = doc.member("appPort") {
            ctx.add(
                "DCG014",
                m.key_pos,
                "appPort publishes ports on all host interfaces (0.0.0.0); use forwardPorts, which stays on localhost".into(),
            );
        }
        for a in &args {
            if a.flag == "-P" || a.flag == "--publish-all" {
                ctx.add(
                    "DCG014",
                    a.node.pos,
                    format!(
                        "runArgs {} publishes every exposed port on all host interfaces",
                        a.flag
                    ),
                );
            }
            if matches!(a.flag.as_str(), "-p" | "--publish")
                && let Some(v) = &a.value
            {
                let v = v.trim();
                let loopback =
                    v.starts_with("127.") || v.starts_with("localhost:") || v.starts_with("[::1]");
                if !loopback {
                    ctx.add(
                        "DCG014",
                        a.node.pos,
                        format!("runArgs {} {v} publishes on all host interfaces; bind to 127.0.0.1 or use forwardPorts", a.flag),
                    );
                }
            }
        }

        if doc.member("name").is_none() {
            ctx.add(
                "DCG016",
                doc.pos,
                "devcontainer.json has no 'name'; set one so the container is identifiable in editors and Codespaces".into(),
            );
        }
    } else {
        for key in ["id", "version"] {
            if doc.member(key).is_none() {
                ctx.add(
                    "DCG016",
                    doc.pos,
                    format!("devcontainer-feature.json has no '{key}', which is required to publish the Feature"),
                );
            }
        }
    }

    // DCG017 agent autonomy + host access
    let host_access: Vec<&'static str> = {
        let mut v: Vec<_> = ctx
            .out
            .iter()
            .map(|f| f.rule)
            .filter(|r| HOST_ACCESS.contains(r))
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    if !host_access.is_empty() {
        let mut hits = Vec::new();
        doc.walk_strings(&mut |n, s| {
            if let Some(m) = AGENT_YOLO.find(s) {
                hits.push((n.pos, m.as_str().trim().to_string()));
            }
        });
        for (pos, flag) in hits {
            ctx.add(
                "DCG017",
                pos,
                format!(
                    "AI agent approvals are disabled ('{flag}') while the container has host access ({}); a prompt injection can reach the host. Remove the host access or keep approvals on",
                    host_access.join(", ")
                ),
            );
        }
    }

    ctx.out
}

fn is_root(u: &str) -> bool {
    let u = u.trim();
    u == "root" || u == "0" || u.starts_with("root:") || u.starts_with("0:")
}
