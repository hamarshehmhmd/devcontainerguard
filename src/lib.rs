//! devcontainerguard: a fast security and best-practice linter for
//! `devcontainer.json` and `devcontainer-feature.json`.

pub mod config;
pub mod jsonc;
pub mod output;
pub mod rules;

use serde::Serialize;
use std::path::{Path, PathBuf};

pub use config::Config;

/// Finding severity, ordered from least to most severe.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, serde::Deserialize, Hash,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "warning" | "warn" => Ok(Severity::Warning),
            "error" => Ok(Severity::Error),
            "never" | "none" => Err("never".into()),
            o => Err(format!("unknown severity '{o}'")),
        }
    }
}

/// What kind of file is being linted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `devcontainer.json` / `.devcontainer.json`
    DevContainer,
    /// `devcontainer-feature.json`
    Feature,
}

impl Kind {
    /// Infer the kind from a file name.
    pub fn for_path(path: &Path) -> Kind {
        match path.file_name().and_then(|n| n.to_str()) {
            Some("devcontainer-feature.json") => Kind::Feature,
            _ => Kind::DevContainer,
        }
    }
}

/// A single lint finding.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub message: String,
    pub line: usize,
    pub column: usize,
}

/// Findings for one file.
#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub path: String,
    pub findings: Vec<Finding>,
}

const IGNORE: &str = "devcontainerguard-ignore";

fn parse_ignore(text: &str) -> Option<Vec<String>> {
    let idx = text.find(IGNORE)?;
    let rest = &text[idx + IGNORE.len()..];
    if rest.starts_with("-file") {
        return None;
    }
    let rest = rest.trim_start_matches(':');
    let ids: Vec<String> = rest
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(|s| s.trim_end_matches("*/").to_uppercase())
        .take_while(|s| s.is_empty() || s.starts_with("DCG"))
        .filter(|s| !s.is_empty())
        .collect();
    if ids.is_empty() {
        Some(vec!["ALL".into()])
    } else {
        Some(ids)
    }
}

/// Collect (start_line, end_line) of every value and member.
fn spans(node: &jsonc::Node, out: &mut Vec<(usize, usize)>) {
    out.push((node.pos.line, node.end_line));
    match &node.value {
        jsonc::Value::Array(items) => items.iter().for_each(|n| spans(n, out)),
        jsonc::Value::Object(members) => {
            for m in members {
                out.push((m.key_pos.line, m.value.end_line));
                spans(&m.value, out);
            }
        }
        _ => {}
    }
}

/// Lint file contents. Returns an error string if the JSONC cannot be parsed.
pub fn lint_str(src: &str, kind: Kind, cfg: &Config) -> Result<Vec<Finding>, String> {
    let doc = jsonc::parse(src).map_err(|e| format!("invalid JSONC at {e}"))?;
    if doc
        .comments
        .iter()
        .any(|c| c.text.contains("devcontainerguard-ignore-file"))
    {
        return Ok(vec![]);
    }

    // Build (line range, ids) suppressions from inline comments.
    let lines: Vec<&str> = src.lines().collect();
    let mut all_spans = Vec::new();
    spans(&doc.root, &mut all_spans);
    let mut suppress: Vec<(usize, usize, Vec<String>)> = Vec::new();
    for c in &doc.comments {
        let Some(ids) = parse_ignore(&c.text) else {
            continue;
        };
        suppress.push((c.pos.line, c.pos.line, ids.clone()));
        if c.own_line {
            let after = c.pos.line + c.text.matches('\n').count();
            let next = (after..lines.len()).map(|i| i + 1).find(|&ln| {
                let t = lines[ln - 1].trim();
                !(t.is_empty() || t.starts_with("//") || t.starts_with("/*") || t.starts_with('*'))
            });
            if let Some(ln) = next {
                let end = all_spans
                    .iter()
                    .filter(|(s, _)| *s == ln)
                    .map(|(_, e)| *e)
                    .max()
                    .unwrap_or(ln);
                suppress.push((ln, end, ids));
            }
        }
    }

    let mut out = Vec::new();
    for mut f in rules::check(&doc.root, kind) {
        if !cfg.enabled(f.rule) {
            continue;
        }
        let ignored = suppress.iter().any(|(s, e, ids)| {
            (*s..=*e).contains(&f.line) && ids.iter().any(|i| i == f.rule || i == "ALL")
        });
        if ignored {
            continue;
        }
        if let Some(sev) = cfg.severity_override(f.rule) {
            f.severity = sev;
        }
        out.push(f);
    }
    out.sort_by(|a, b| (a.line, a.column, a.rule).cmp(&(b.line, b.column, b.rule)));
    out.dedup();
    Ok(out)
}

fn is_target(name: &str) -> bool {
    matches!(
        name,
        "devcontainer.json" | ".devcontainer.json" | "devcontainer-feature.json"
    )
}

const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", "vendor", ".venv", "dist"];

/// Expand paths: files are kept as-is, directories are searched recursively
/// for `devcontainer.json`, `.devcontainer.json` and `devcontainer-feature.json`.
pub fn discover(paths: &[PathBuf]) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            walk(p, &mut out)?;
        } else {
            out.push(p.clone());
        }
    }
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        let ft = e.file_type()?;
        if ft.is_dir() {
            if !SKIP_DIRS.contains(&name.as_ref()) {
                walk(&path, out)?;
            }
        } else if is_target(&name) {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_comment_parsing() {
        assert_eq!(
            parse_ignore(" devcontainerguard-ignore DCG001, dcg002 because"),
            Some(vec!["DCG001".into(), "DCG002".into()])
        );
        assert_eq!(
            parse_ignore(" devcontainerguard-ignore"),
            Some(vec!["ALL".into()])
        );
        assert_eq!(parse_ignore(" devcontainerguard-ignore-file"), None);
        assert_eq!(parse_ignore(" nothing"), None);
    }

    #[test]
    fn kind_detection() {
        assert_eq!(
            Kind::for_path(Path::new("src/x/devcontainer-feature.json")),
            Kind::Feature
        );
        assert_eq!(
            Kind::for_path(Path::new(".devcontainer/devcontainer.json")),
            Kind::DevContainer
        );
    }
}
