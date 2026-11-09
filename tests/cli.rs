use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_devcontainerguard"))
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

const INSECURE: &str = "tests/fixtures/insecure/.devcontainer/devcontainer.json";

#[test]
fn exit_codes() {
    assert_eq!(run(&[INSECURE]).0, 1);
    assert_eq!(run(&["tests/fixtures/secure"]).0, 0);
    assert_eq!(run(&["--fail-on", "never", INSECURE]).0, 0);
    assert_eq!(
        run(&["--fail-on", "error", "tests/fixtures/agent-sandbox"]).0,
        0
    );
    assert_eq!(
        run(&["--fail-on", "info", "tests/fixtures/agent-sandbox"]).0,
        1
    );
    assert_eq!(run(&["does-not-exist.json"]).0, 2);
    let (code, _, err) = run(&["tests/fixtures/broken.json"]);
    assert_eq!(code, 2);
    assert!(err.contains("invalid JSONC"));
    assert_eq!(run(&["--ignore", "DCG999", INSECURE]).0, 2);
}

#[test]
fn directory_discovery_finds_all_kinds() {
    let (_, out, _) = run(&["-f", "json", "--fail-on", "never", "tests/fixtures"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let paths: Vec<String> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["path"].as_str().unwrap().replace('\\', "/"))
        .collect();
    assert!(
        paths
            .iter()
            .any(|p| p.ends_with("secure/.devcontainer/python/devcontainer.json"))
    );
    assert!(
        paths
            .iter()
            .any(|p| p.ends_with("devcontainer-feature.json"))
    );
    assert!(
        paths
            .iter()
            .any(|p| p.ends_with("skipfile/.devcontainer.json"))
    );
    assert!(!paths.iter().any(|p| p.ends_with("broken.json")));
}

#[test]
fn ignore_path_glob() {
    let (code, out, _) = run(&[
        "--ignore-path",
        "**/insecure/**",
        "--ignore-path",
        "**/feature/**",
        "--ignore-path",
        "**/ignored/**",
        "tests/fixtures",
    ]);
    assert_eq!(code, 0, "{out}");
}

#[test]
fn sarif_is_valid() {
    let (_, out, _) = run(&["-f", "sarif", INSECURE]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["version"], "2.1.0");
    let results = v["runs"][0]["results"].as_array().unwrap();
    assert!(results.len() >= 20);
    assert!(results[0]["locations"][0]["physicalLocation"]["region"]["startColumn"].is_number());
    assert_eq!(
        v["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .len(),
        20
    );
}

#[test]
fn json_and_github_formats() {
    let (_, out, _) = run(&["-f", "json", INSECURE]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(v[0]["findings"].as_array().unwrap().len() >= 20);
    let (_, gh, _) = run(&["-f", "github", INSECURE]);
    assert!(
        gh.contains(&format!(
            "::error file={INSECURE},line=5,col=17,title=DCG001::"
        )),
        "{gh}"
    );
}

#[test]
fn config_file() {
    let (code, _, _) = run(&[
        "-c",
        "tests/fixtures/strict.yaml",
        "tests/fixtures/agent-sandbox",
    ]);
    assert_eq!(code, 1);
}

#[test]
fn list_rules() {
    let (code, out, _) = run(&["--list-rules"]);
    assert_eq!(code, 0);
    assert!(out.contains("DCG020"));
    assert_eq!(out.lines().count(), 20);
}
