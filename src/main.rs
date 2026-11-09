use clap::{Parser, ValueEnum};
use devcontainerguard::config::{Config, DEFAULT_CONFIG};
use devcontainerguard::{FileReport, Kind, Severity, discover, lint_str, output, rules::RULES};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
    Sarif,
    Github,
}

/// Fast security and best-practice linter for devcontainer.json and Dev Container Features.
///
/// Exit codes: 0 = no findings at or above --fail-on, 1 = findings, 2 = usage/parse error.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Files or directories to lint. Directories are searched recursively for
    /// devcontainer.json, .devcontainer.json and devcontainer-feature.json.
    /// Defaults to the current directory.
    paths: Vec<PathBuf>,
    /// Output format.
    #[arg(short, long, value_enum, default_value = "human")]
    format: Format,
    /// Config file (default: .devcontainerguard.yaml if present).
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Minimum severity that causes exit code 1: info, warning, error, never.
    #[arg(long)]
    fail_on: Option<String>,
    /// Disable a rule (repeatable).
    #[arg(long = "ignore", value_name = "RULE")]
    ignore: Vec<String>,
    /// Skip files matching a glob (repeatable), e.g. 'examples/**'.
    #[arg(long = "ignore-path", value_name = "GLOB")]
    ignore_path: Vec<String>,
    /// List all rules and exit.
    #[arg(long)]
    list_rules: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.list_rules {
        for r in RULES {
            println!(
                "{}  {:<8} {:<32} {}",
                r.id,
                r.severity.as_str(),
                r.name,
                r.description
            );
        }
        return ExitCode::SUCCESS;
    }
    let mut cfg = match &cli.config {
        Some(p) => Config::load(p),
        None if Path::new(DEFAULT_CONFIG).exists() => Config::load(Path::new(DEFAULT_CONFIG)),
        None => Ok(Config::default()),
    }
    .unwrap_or_else(|e| fatal(&format!("config error: {e}")));
    for id in &cli.ignore {
        if devcontainerguard::rules::rule(&id.to_uppercase()).is_none() {
            fatal(&format!("unknown rule id '{id}'"));
        }
    }
    cfg.ignore.extend(cli.ignore.iter().cloned());
    cfg.add_ignore_paths(cli.ignore_path.clone())
        .unwrap_or_else(|e| fatal(&e));

    let fail_on = cli
        .fail_on
        .clone()
        .or(cfg.fail_on.clone())
        .unwrap_or_else(|| "warning".into());
    let threshold: Option<Severity> = match fail_on.parse() {
        Ok(s) => Some(s),
        Err(e) if e == "never" => None,
        Err(e) => fatal(&e),
    };

    let inputs = if cli.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        cli.paths.clone()
    };
    for p in &inputs {
        if !p.exists() {
            fatal(&format!("{}: no such file or directory", p.display()));
        }
    }
    let files: Vec<PathBuf> = discover(&inputs)
        .unwrap_or_else(|e| fatal(&e.to_string()))
        .into_iter()
        .filter(|p| !cfg.path_ignored(&p.display().to_string()))
        .collect();
    if files.is_empty() {
        fatal("no devcontainer.json or devcontainer-feature.json found; pass a path");
    }

    let mut reports = Vec::new();
    let mut parse_errors = false;
    for f in &files {
        let display = f.display().to_string();
        let display = display.strip_prefix("./").unwrap_or(&display).to_string();
        let src = match std::fs::read_to_string(f) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("devcontainerguard: {display}: {e}");
                parse_errors = true;
                continue;
            }
        };
        match lint_str(&src, Kind::for_path(f), &cfg) {
            Ok(findings) => reports.push(FileReport {
                path: display,
                findings,
            }),
            Err(e) => {
                eprintln!("devcontainerguard: {display}: {e}");
                parse_errors = true;
            }
        }
    }

    let text = match cli.format {
        Format::Human => output::human(&reports),
        Format::Json => output::json(&reports),
        Format::Sarif => output::sarif(&reports),
        Format::Github => output::github(&reports),
    };
    print!("{text}");
    if matches!(cli.format, Format::Json | Format::Sarif) {
        println!();
    }

    if parse_errors {
        return ExitCode::from(2);
    }
    let failed = threshold.is_some_and(|t| {
        reports
            .iter()
            .flat_map(|r| &r.findings)
            .any(|f| f.severity >= t)
    });
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn fatal(msg: &str) -> ! {
    eprintln!("devcontainerguard: {msg}");
    std::process::exit(2)
}
