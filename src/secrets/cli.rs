use clap::{ArgAction, Parser};
use std::path::PathBuf;
use crate::secrets::report::OutputFormat;
use crate::secrets::rules::types::Severity;

/// Fast, multi-threaded static asset scanner to detect Cloudflare server secret leaks in client bundles.
#[derive(Parser, Debug)]
#[command(
    name = "cf-secret-leak-guard",
    version,
    about = "Prevent Cloudflare server-side secrets from leaking into client-side static assets",
    long_about = "cf-secret-leak-guard scans static web asset directories (dist/client, dist/_astro, public) \
for Cloudflare server-side credentials, API tokens, Turnstile secret keys, Origin CA keys, and .dev.vars / .env values."
)]
pub struct Cli {
    /// Target asset directories or files to scan (default: auto-detect dist/client, dist/_astro, public)
    #[arg(value_name = "TARGETS")]
    pub targets: Vec<PathBuf>,

    /// Additional target directory or file to scan (can be specified multiple times)
    #[arg(short = 't', long = "target", action = ArgAction::Append)]
    pub additional_targets: Vec<PathBuf>,

    /// CI gate check: Exit with code 1 if any server secrets are detected
    #[arg(long, help = "Exit with non-zero exit code (1) if leaks are detected")]
    pub check: bool,

    /// Report output format (text, json, sarif)
    #[arg(short = 'f', long = "format", value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Write report output to a specified file instead of stdout
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Environment or vars file (.dev.vars, .env, wrangler.jsonc) to extract secret values from
    #[arg(short = 'e', long = "env-file", action = ArgAction::Append, value_name = "ENV_FILE")]
    pub env_files: Vec<PathBuf>,

    /// Disable auto-discovery of .env, .dev.vars, and wrangler config files
    #[arg(long, help = "Disable automatic discovery of .dev.vars and .env files")]
    pub no_auto_env: bool,

    /// Glob patterns of files to exclude from scanning (e.g. '*.map')
    #[arg(long = "exclude", action = ArgAction::Append, value_name = "GLOB")]
    pub excludes: Vec<String>,

    /// Specific rule IDs to ignore (e.g. 'CF-006')
    #[arg(long = "ignore-rule", action = ArgAction::Append, value_name = "RULE_ID")]
    pub ignore_rules: Vec<String>,

    /// Specific secret strings to allowlist/ignore
    #[arg(long = "ignore-secret", action = ArgAction::Append, value_name = "SECRET")]
    pub ignore_secrets: Vec<String>,

    /// Path to .cfsecretignore configuration file
    #[arg(long = "ignore-file", value_name = "FILE")]
    pub ignore_file: Option<PathBuf>,

    /// Maximum file size to scan in megabytes (default: 50MB)
    #[arg(long = "max-file-size", default_value_t = 50, value_name = "MB")]
    pub max_file_size_mb: u64,

    /// Minimum severity level to report (low, medium, high, critical)
    #[arg(long = "min-severity", default_value_t = Severity::Low, value_name = "SEVERITY")]
    pub min_severity: Severity,

    /// Number of worker threads for parallel scanning (default: auto)
    #[arg(long = "threads", value_name = "NUM")]
    pub threads: Option<usize>,

    /// List all built-in secret detection rules and exit
    #[arg(long = "list-rules", help = "List all built-in Cloudflare secret detection rules and exit")]
    pub list_rules: bool,

    /// Suppress informative terminal messages
    #[arg(short = 'q', long = "quiet", help = "Quiet mode (suppress non-error output)")]
    pub quiet: bool,

    /// Show verbose scanning information and remediation steps
    #[arg(short = 'v', long = "verbose", help = "Verbose mode (print detailed progress and remediation)")]
    pub verbose: bool,
}
