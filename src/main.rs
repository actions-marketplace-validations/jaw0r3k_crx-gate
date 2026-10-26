use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use crx_gate::config::Config;
use crx_gate::signatures::BUILTIN_RULES;
use crx_gate::{render_json_report, render_markdown_report, render_terminal_report, generate_sarif_report, Scanner};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "crx-gate",
    author = "crx-gate contributors",
    version,
    about = "Zero-dependency CLI for pre-commit extension security, permission blast-radius auditing, and CWS rejection prediction",
    long_about = "crx-gate statically analyzes unpacked extension directories, .zip bundles, or .crx binary archives in under 200ms. It outputs a deterministic blast-radius score, flags dead or over-privileged permissions, detects hidden data-exfiltration sinks via static taint analysis, and predicts Chrome Web Store rejection triggers before submission."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to extension directory, .zip, or .crx archive (shorthand for 'audit <PATH>')
    #[arg(global = true)]
    path: Option<PathBuf>,

    /// Output format: table, json, sarif, markdown
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Table, global = true)]
    format: OutputFormat,

    /// Write report to output file instead of stdout
    #[arg(short, long, global = true)]
    output: Option<PathBuf>,

    /// Fail threshold: none, low, medium, high, critical
    #[arg(long, global = true)]
    fail_on: Option<String>,

    /// Maximum permissible blast radius score (0-100) before exiting with code 1
    #[arg(long, global = true)]
    max_score: Option<u32>,

    /// Path to custom crx-gate.toml configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Print timing benchmark breakdown
    #[arg(long, global = true)]
    benchmark: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Audit an extension directory, .zip, or .crx archive
    Audit {
        /// Target path to scan
        path: PathBuf,
    },
    /// Compare blast-radius and security posture between two extension versions
    Diff {
        /// Base version path (e.g. previous release or HEAD~1)
        base: PathBuf,
        /// Target version path (e.g. current PR branch)
        target: PathBuf,
        /// Fail if target has a higher blast radius than base
        #[arg(long)]
        fail_on_degradation: bool,
    },
    /// List all built-in security rules and Chrome Web Store rejection heuristics
    Rules {
        /// Filter rules by category or severity
        #[arg(short, long)]
        category: Option<String>,
    },
    /// Git hook integration helper
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum HookAction {
    /// Generate a pre-commit git hook script for your repository
    Install {
        /// Directory of the git repository (default: current directory)
        #[arg(default_value = ".")]
        repo_dir: PathBuf,
        /// Path to extension directory relative to repository root
        #[arg(default_value = ".")]
        ext_dir: PathBuf,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Table,
    Json,
    Sarif,
    Markdown,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = Config::load_or_default(cli.config.as_deref());

    match &cli.command {
        Some(Commands::Audit { path }) => run_audit(path.clone(), &cli, &config),
        Some(Commands::Diff {
            base,
            target,
            fail_on_degradation,
        }) => run_diff(base.clone(), target.clone(), *fail_on_degradation, &cli, &config),
        Some(Commands::Rules { category }) => run_rules(category.clone()),
        Some(Commands::Hook { action }) => run_hook(action.clone()),
        None => {
            if let Some(path) = &cli.path {
                run_audit(path.clone(), &cli, &config)
            } else {
                eprintln!(
                    "{}",
                    "Error: No extension path provided. Run 'crx-gate audit <PATH>' or 'crx-gate --help'.".bright_red()
                );
                ExitCode::from(1)
            }
        }
    }
}

fn run_audit(path: PathBuf, cli: &Cli, config: &Config) -> ExitCode {
    let scanner = Scanner::new(config.clone());

    match scanner.scan(&path) {
        Ok(result) => {
            let rendered = match cli.format {
                OutputFormat::Table => render_terminal_report(
                    &result.target_path,
                    &result.package_type,
                    result.extension_id.as_deref(),
                    &result.extension_name,
                    &result.extension_version,
                    result.manifest_version,
                    &result.score,
                    &result.findings,
                    &result.taint_paths,
                    result.execution_duration_ms,
                ),
                OutputFormat::Json => render_json_report(
                    &result.target_path,
                    &result.package_type,
                    result.extension_id.as_deref(),
                    &result.extension_name,
                    &result.extension_version,
                    result.manifest_version,
                    &result.score,
                    &result.findings,
                    &result.taint_paths,
                    result.execution_duration_ms,
                ),
                OutputFormat::Sarif => {
                    let sarif = generate_sarif_report(&result.findings);
                    serde_json::to_string_pretty(&sarif).unwrap_or_default()
                }
                OutputFormat::Markdown => render_markdown_report(
                    &result.target_path,
                    &result.package_type,
                    result.extension_id.as_deref(),
                    &result.extension_name,
                    &result.extension_version,
                    result.manifest_version,
                    &result.score,
                    &result.findings,
                    &result.taint_paths,
                    result.execution_duration_ms,
                ),
            };

            if let Some(out_path) = &cli.output {
                if let Err(e) = fs::write(out_path, &rendered) {
                    eprintln!("Failed to write report to {}: {}", out_path.display(), e);
                    return ExitCode::from(1);
                }
                println!("Report successfully written to {}", out_path.display().to_string().green());
            } else {
                print!("{}", rendered);
            }

            if cli.benchmark {
                eprintln!(
                    "\n[Benchmark] Completed AST traversal, taint graph BFS, and permission blast scoring in {}ms ({} µs)",
                    result.execution_duration_ms,
                    result.execution_duration_ms * 1000
                );
            }

            // Check failure conditions
            let fail_on_str = cli
                .fail_on
                .as_deref()
                .unwrap_or(&config.audit.fail_on)
                .to_lowercase();

            let max_score = cli.max_score.unwrap_or(config.audit.max_score);

            if result.score.total_score > max_score {
                eprintln!(
                    "\n{} Blast-radius score ({} / 100) exceeds maximum permissible threshold ({})!",
                    "✕ Gate Failure:".bright_red().bold(),
                    result.score.total_score,
                    max_score
                );
                return ExitCode::from(1);
            }

            let has_failing_severity = match fail_on_str.as_str() {
                "critical" => result.score.critical_count > 0,
                "high" => result.score.critical_count > 0 || result.score.high_count > 0,
                "medium" => {
                    result.score.critical_count > 0
                        || result.score.high_count > 0
                        || result.score.medium_count > 0
                }
                "low" => {
                    result.score.critical_count > 0
                        || result.score.high_count > 0
                        || result.score.medium_count > 0
                        || result.score.low_count > 0
                }
                "none" => false,
                _ => result.score.critical_count > 0 || result.score.high_count > 0,
            };

            if has_failing_severity {
                eprintln!(
                    "\n{} Extension security audit detected findings meeting or exceeding fail threshold ('{}')!",
                    "✕ Gate Failure:".bright_red().bold(),
                    fail_on_str
                );
                return ExitCode::from(1);
            }

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}: {:#}", "Scan Error".bright_red().bold(), e);
            ExitCode::from(1)
        }
    }
}

fn run_diff(
    base: PathBuf,
    target: PathBuf,
    fail_on_degradation: bool,
    cli: &Cli,
    config: &Config,
) -> ExitCode {
    let scanner = Scanner::new(config.clone());
    match scanner.diff(&base, &target) {
        Ok(diff) => {
            let rendered = match cli.format {
                OutputFormat::Json => serde_json::to_string_pretty(&diff).unwrap_or_default(),
                _ => diff.render_terminal(),
            };

            if let Some(out_path) = &cli.output {
                let _ = fs::write(out_path, &rendered);
                println!("Diff report written to {}", out_path.display());
            } else {
                print!("{}", rendered);
            }

            if fail_on_degradation && diff.score_delta > 0 {
                eprintln!(
                    "{}",
                    "✕ Diff Failure: Blast radius degradation detected in target extension build!"
                        .bright_red()
                        .bold()
                );
                return ExitCode::from(1);
            }

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{}: {:#}", "Diff Error".bright_red().bold(), e);
            ExitCode::from(1)
        }
    }
}

fn run_rules(category_filter: Option<String>) -> ExitCode {
    println!("\n{}", "CRX-GATE — Curated Threat Intel & CWS Signature Database".bright_cyan().bold());
    println!("Total Rules: {}\n", BUILTIN_RULES.len());

    for rule in BUILTIN_RULES {
        if let Some(cat) = &category_filter {
            if !rule.category.to_lowercase().contains(&cat.to_lowercase()) {
                continue;
            }
        }

        let sev_colored = match rule.default_severity.as_str() {
            "critical" => "CRITICAL".bright_red().bold(),
            "high" => "HIGH".bright_red(),
            "medium" => "MEDIUM".yellow(),
            _ => "LOW".blue(),
        };

        println!(
            "• [{}] {} — {} ({})",
            sev_colored,
            rule.id.cyan().bold(),
            rule.title.bold(),
            rule.category.dimmed()
        );
        println!("  Description: {}", rule.description);
        if let Some(cws) = rule.cws_policy_reference {
            println!("  Policy Ref:  {}", cws.bright_yellow());
        }
        println!("  Fix:         {}\n", rule.remediation.green());
    }

    ExitCode::SUCCESS
}

fn run_hook(action: HookAction) -> ExitCode {
    match action {
        HookAction::Install { repo_dir, ext_dir } => {
            let hooks_dir = repo_dir.join(".git").join("hooks");
            if !hooks_dir.exists() {
                eprintln!(
                    "{} .git/hooks directory not found in '{}'. Ensure this is a git repository.",
                    "Error:".bright_red(),
                    repo_dir.display()
                );
                return ExitCode::from(1);
            }

            let hook_path = hooks_dir.join("pre-commit");
            let hook_script = format!(
                r#"#!/bin/sh
# crx-gate pre-commit security gate
echo "🛡️ Running crx-gate pre-commit extension security audit..."

crx-gate audit "{}" --fail-on high --max-score 60
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo "❌ crx-gate pre-commit audit failed! Fix flagged issues or update crx-gate.toml before committing."
  exit 1
fi

echo "✅ crx-gate audit passed!"
exit 0
"#,
                ext_dir.display().to_string().replace('\\', "/")
            );

            if let Err(e) = fs::write(&hook_path, hook_script) {
                eprintln!("Failed to write hook file: {}", e);
                return ExitCode::from(1);
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = fs::metadata(&hook_path) {
                    let mut perms = metadata.permissions();
                    perms.set_mode(0o755);
                    let _ = fs::set_permissions(&hook_path, perms);
                }
            }

            println!(
                "{} Installed pre-commit hook at {}",
                "✓ Success:".bright_green().bold(),
                hook_path.display()
            );
            ExitCode::SUCCESS
        }
    }
}
