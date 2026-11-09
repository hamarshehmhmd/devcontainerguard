//! `.devcontainerguard.yaml` configuration.

use crate::Severity;
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Default config file name searched in the working directory.
pub const DEFAULT_CONFIG: &str = ".devcontainerguard.yaml";

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    ignore: Vec<String>,
    #[serde(default)]
    fail_on: Option<String>,
    #[serde(default)]
    severity: HashMap<String, Severity>,
    #[serde(default)]
    ignore_paths: Vec<String>,
}

/// Effective configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Rule IDs to disable entirely.
    pub ignore: Vec<String>,
    /// Lowest severity that makes the process exit non-zero (default: warning).
    pub fail_on: Option<String>,
    /// Per-rule severity overrides.
    pub severity: HashMap<String, Severity>,
    /// Glob patterns of files to skip.
    pub ignore_paths: Vec<String>,
    globs: Option<GlobSet>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        if text.trim().is_empty() {
            return Ok(Self::default());
        }
        let raw: RawConfig = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        for id in raw.ignore.iter().chain(raw.severity.keys()) {
            if crate::rules::rule(&id.to_uppercase()).is_none() {
                return Err(format!("unknown rule id '{id}'"));
            }
        }
        let mut cfg = Config {
            ignore: raw.ignore,
            fail_on: raw.fail_on,
            severity: raw.severity,
            ignore_paths: Vec::new(),
            globs: None,
        };
        cfg.add_ignore_paths(raw.ignore_paths)?;
        Ok(cfg)
    }

    /// Add glob patterns (e.g. `examples/**`) of files to skip.
    pub fn add_ignore_paths(&mut self, patterns: Vec<String>) -> Result<(), String> {
        self.ignore_paths.extend(patterns);
        let mut b = GlobSetBuilder::new();
        for p in &self.ignore_paths {
            b.add(Glob::new(p).map_err(|e| format!("invalid ignore_paths glob '{p}': {e}"))?);
        }
        self.globs = Some(b.build().map_err(|e| e.to_string())?);
        Ok(())
    }

    pub fn enabled(&self, id: &str) -> bool {
        !self.ignore.iter().any(|i| i.eq_ignore_ascii_case(id))
    }

    pub fn severity_override(&self, id: &str) -> Option<Severity> {
        self.severity
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(id))
            .map(|(_, v)| *v)
    }

    /// True if `path` matches an `ignore_paths` glob.
    pub fn path_ignored(&self, path: &str) -> bool {
        let p = path.replace('\\', "/");
        let p = p.trim_start_matches("./");
        self.globs.as_ref().is_some_and(|g| g.is_match(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let c = Config::parse(
            "ignore: [DCG016]\nfail_on: error\nseverity:\n  dcg007: error\nignore_paths:\n  - 'examples/**'\n",
        )
        .unwrap();
        assert!(!c.enabled("dcg016"));
        assert_eq!(c.severity_override("DCG007"), Some(Severity::Error));
        assert!(c.path_ignored("./examples/a/.devcontainer/devcontainer.json"));
        assert!(!c.path_ignored(".devcontainer/devcontainer.json"));
    }

    #[test]
    fn rejects_unknown_rules_and_keys() {
        assert!(Config::parse("ignore: [DCG999]").is_err());
        assert!(Config::parse("bogus: 1").is_err());
        assert!(Config::parse("").unwrap().enabled("DCG001"));
    }
}
