use devcontainerguard::{Config, Kind, Severity, lint_str};
use std::collections::BTreeSet;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn ids_of(src: &str, kind: Kind, cfg: &Config) -> BTreeSet<&'static str> {
    lint_str(src, kind, cfg)
        .unwrap()
        .into_iter()
        .map(|f| f.rule)
        .collect()
}

fn ids(src: &str) -> BTreeSet<&'static str> {
    ids_of(src, Kind::DevContainer, &Config::default())
}

const INSECURE: &str = "insecure/.devcontainer/devcontainer.json";

#[test]
fn insecure_fixture_triggers_every_rule() {
    let got = ids(&fixture(INSECURE));
    for r in devcontainerguard::rules::RULES {
        assert!(got.contains(r.id), "expected {} to fire, got {got:?}", r.id);
    }
}

#[test]
fn rule_count_and_ids_are_stable() {
    let rules = devcontainerguard::rules::RULES;
    assert_eq!(rules.len(), 20);
    for (i, r) in rules.iter().enumerate() {
        assert_eq!(r.id, format!("DCG{:03}", i + 1));
    }
}

#[test]
fn secure_fixtures_are_clean() {
    for f in [
        "secure/.devcontainer/python/devcontainer.json",
        "secure/.devcontainer/node/devcontainer.json",
    ] {
        let got = lint_str(&fixture(f), Kind::DevContainer, &Config::default()).unwrap();
        assert!(got.is_empty(), "{f}: {got:#?}");
    }
}

#[test]
fn agent_sandbox_reference_only_gets_info() {
    let got = lint_str(
        &fixture("agent-sandbox/.devcontainer/devcontainer.json"),
        Kind::DevContainer,
        &Config::default(),
    )
    .unwrap();
    assert!(!got.is_empty());
    assert!(
        got.iter()
            .all(|f| f.rule == "DCG019" && f.severity == Severity::Info),
        "{got:#?}"
    );
}

#[test]
fn findings_have_line_and_column() {
    let got = lint_str(&fixture(INSECURE), Kind::DevContainer, &Config::default()).unwrap();
    let p = got.iter().find(|f| f.rule == "DCG001").unwrap();
    assert_eq!((p.line, p.column), (5, 17));
    let sock = got.iter().find(|f| f.rule == "DCG002").unwrap();
    assert_eq!((sock.line, sock.column), (11, 5));
}

#[test]
fn interpolated_secret_not_flagged() {
    let got = lint_str(&fixture(INSECURE), Kind::DevContainer, &Config::default()).unwrap();
    let secrets: Vec<_> = got.iter().filter(|f| f.rule == "DCG009").collect();
    assert_eq!(secrets.len(), 2);
    assert!(secrets.iter().all(|f| !f.message.contains("GITHUB_TOKEN")));
    assert!(
        secrets.iter().all(|f| !f.message.contains("sk-ant")),
        "secret value must not be echoed"
    );
}

#[test]
fn inline_ignores() {
    let got = ids(&fixture("ignored/devcontainer.json"));
    assert_eq!(got, BTreeSet::from(["DCG005"]));
    assert!(ids(&fixture("skipfile/.devcontainer.json")).is_empty());
}

#[test]
fn config_disables_and_overrides() {
    let cfg = Config::parse("ignore: [DCG016, dcg001]\nseverity:\n  DCG007: error\n").unwrap();
    let got = lint_str(&fixture(INSECURE), Kind::DevContainer, &cfg).unwrap();
    assert!(!got.iter().any(|f| f.rule == "DCG016" || f.rule == "DCG001"));
    assert!(
        got.iter()
            .any(|f| f.rule == "DCG007" && f.severity == Severity::Error)
    );
}

#[test]
fn feature_file_rules() {
    let got = ids_of(
        &fixture("feature/src/hello/devcontainer-feature.json"),
        Kind::Feature,
        &Config::default(),
    );
    assert_eq!(
        got,
        BTreeSet::from(["DCG001", "DCG002", "DCG005", "DCG008", "DCG009", "DCG016"])
    );
}

#[test]
fn parse_error_is_reported_with_position() {
    let e = lint_str(
        &fixture("broken.json"),
        Kind::DevContainer,
        &Config::default(),
    )
    .unwrap_err();
    assert!(e.contains("4:1"), "{e}");
}

#[test]
fn run_args_forms() {
    let src = r#"{"name":"x","image":"a:1","runArgs":["--privileged","--cap-add","ALL","--security-opt=apparmor:unconfined","--net","host","-e","AWS_SECRET_ACCESS_KEY=abc","-u","0","-P","--userns=host"]}"#;
    let got = ids(src);
    for id in [
        "DCG001", "DCG004", "DCG005", "DCG006", "DCG009", "DCG010", "DCG014",
    ] {
        assert!(got.contains(id), "{id} missing: {got:?}");
    }
}

#[test]
fn mount_variants() {
    let src = r#"{"name":"x","image":"a:1","mounts":[
        "type=bind,src=/,dst=/host",
        "source=${localEnv:HOME}${localEnv:USERPROFILE},target=/h,type=bind",
        "source=${localEnv:HOME}/.config/gh,target=/gh,type=bind",
        "source=${localEnv:HOME}/.aws,target=/aws,type=volume",
        "source=/home/me/.kube/,target=/k,type=bind"
    ]}"#;
    let got = lint_str(src, Kind::DevContainer, &Config::default()).unwrap();
    assert_eq!(
        got.iter().filter(|f| f.rule == "DCG003").count(),
        3,
        "{got:#?}"
    );
    assert_eq!(got.iter().filter(|f| f.rule == "DCG018").count(), 1);
}

#[test]
fn image_and_feature_pinning() {
    assert!(ids(r#"{"name":"x","image":"ubuntu"}"#).contains("DCG007"));
    assert!(!ids(r#"{"name":"x","image":"ubuntu@sha256:abc"}"#).contains("DCG007"));
    assert!(!ids(r#"{"name":"x","image":"localhost:5000/img:1.2"}"#).contains("DCG007"));
    assert!(ids(r#"{"name":"x","image":"a:1","features":{"node":{}}}"#).contains("DCG008"));
    assert!(
        !ids(r#"{"name":"x","image":"a:1","features":{"ghcr.io/x/y/z:1":{}}}"#).contains("DCG008")
    );
}

#[test]
fn pipe_to_shell_variants() {
    for cmd in [
        r#""wget -qO- https://x.sh | sudo -E bash -""#,
        r#""sh -c \"$(curl -fsSL https://x)\"""#,
        r#"["bash", "-c", "curl -L x | sh"]"#,
        r#"{"a": "echo ok", "b": "bash <(curl -s https://x)"}"#,
    ] {
        let src = format!(r#"{{"name":"x","image":"a:1","postCreateCommand": {cmd}}}"#);
        assert!(ids(&src).contains("DCG011"), "{cmd}");
    }
    assert!(!ids(r#"{"name":"x","image":"a:1","postCreateCommand":"curl -o x https://x && sha256sum -c x.sha"}"#).contains("DCG011"));
}

#[test]
fn agent_yolo_without_host_access_is_not_dcg017() {
    let src = r#"{"name":"x","image":"a:1","postAttachCommand":"codex --dangerously-bypass-approvals-and-sandbox"}"#;
    assert!(!ids(src).contains("DCG017"));
    let src = r#"{"name":"x","image":"a:1","runArgs":["--network=host"],"postAttachCommand":"gemini --yolo"}"#;
    assert!(ids(src).contains("DCG017"));
}

#[test]
fn compose_and_build_conflict() {
    let got = lint_str(
        r#"{"name":"x","image":"a:1","dockerComposeFile":"c.yml","service":"app"}"#,
        Kind::DevContainer,
        &Config::default(),
    )
    .unwrap();
    let c = got.iter().find(|f| f.rule == "DCG013").unwrap();
    assert!(c.message.contains("both set"));
}
