//! Output formatters: human, json, sarif, github.

use crate::rules::RULES;
use crate::{FileReport, Severity};
use serde_json::json;

const DOCS: &str = "https://github.com/hamarshehmhmd/devcontainerguard/blob/main/docs/rules.md";

pub fn human(reports: &[FileReport]) -> String {
    let mut out = String::new();
    let mut total = 0;
    for r in reports {
        for f in &r.findings {
            total += 1;
            let loc = format!("{}:{}:{}", r.path, f.line, f.column);
            out.push_str(&format!(
                "{loc:<44}  {:<7}  {}  {}\n",
                f.severity.as_str(),
                f.rule,
                f.message
            ));
        }
    }
    let count = |s: Severity| {
        reports
            .iter()
            .flat_map(|r| &r.findings)
            .filter(|f| f.severity == s)
            .count()
    };
    if total > 0 {
        out.push('\n');
    }
    out.push_str(&format!(
        "{} problem(s) in {} file(s): {} error, {} warning, {} info\n",
        total,
        reports.len(),
        count(Severity::Error),
        count(Severity::Warning),
        count(Severity::Info)
    ));
    out
}

pub fn json(reports: &[FileReport]) -> String {
    serde_json::to_string_pretty(reports).expect("serializable")
}

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

pub fn sarif(reports: &[FileReport]) -> String {
    let rules: Vec<_> = RULES
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "shortDescription": { "text": r.description },
                "helpUri": format!("{DOCS}#{}", r.id.to_lowercase()),
                "defaultConfiguration": { "level": level(r.severity) },
                "properties": { "tags": ["security", "devcontainer"] }
            })
        })
        .collect();
    let results: Vec<_> = reports
        .iter()
        .flat_map(|r| {
            r.findings.iter().map(move |f| {
                json!({
                    "ruleId": f.rule,
                    "ruleIndex": RULES.iter().position(|x| x.id == f.rule).unwrap_or(0),
                    "level": level(f.severity),
                    "message": { "text": f.message },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": r.path.replace('\\', "/").trim_start_matches("./") },
                            "region": { "startLine": f.line.max(1), "startColumn": f.column.max(1) }
                        }
                    }]
                })
            })
        })
        .collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "devcontainerguard",
                "version": env!("CARGO_PKG_VERSION"),
                "semanticVersion": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/hamarshehmhmd/devcontainerguard",
                "rules": rules
            }},
            "results": results
        }]
    });
    serde_json::to_string_pretty(&doc).expect("serializable")
}

fn escape_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn escape_prop(s: &str) -> String {
    escape_data(s).replace(':', "%3A").replace(',', "%2C")
}

pub fn github(reports: &[FileReport]) -> String {
    let mut out = String::new();
    for r in reports {
        for f in &r.findings {
            let kind = match f.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "notice",
            };
            out.push_str(&format!(
                "::{kind} file={},line={},col={},title={}::{}\n",
                escape_prop(&r.path.replace('\\', "/")),
                f.line.max(1),
                f.column.max(1),
                f.rule,
                escape_data(&f.message)
            ));
        }
    }
    out
}
