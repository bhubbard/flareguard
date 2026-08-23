use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "cf-zone-auditor",
    author = "Antigravity Systems",
    version = env!("CARGO_PKG_VERSION"),
    about = "Cloudflare Zone Security Posture Auditor & Compliance Gate",
    long_about = "Fast, comprehensive security posture auditor for Cloudflare zones.\nScans SSL/TLS modes, TLS versions, HSTS headers, HTTPS enforcement, WAF managed rules,\nBot Fight Mode, rate limiting, DNSSEC, and IP access rules."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[command(flatten)]
    pub audit_args: AuditArgs,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run security posture audit on Cloudflare zones (default command)
    Audit(AuditArgs),

    /// Generate a sample mock JSON file with multiple realistic zone configurations
    GenerateMock {
        /// File path to write the sample JSON to (prints to stdout if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// List all security rules evaluated by cf-zone-auditor
    Rules {
        /// Format for displaying rules (table or json)
        #[arg(short, long, value_enum, default_value = "table")]
        format: RuleListFormat,
    },
}

#[derive(Debug, Args, Clone)]
pub struct AuditArgs {
    /// Cloudflare API Token (can also be supplied via CF_API_TOKEN environment variable)
    #[arg(short, long, env = "CF_API_TOKEN")]
    pub token: Option<String>,

    /// Cloudflare Account ID to filter zones
    #[arg(short = 'a', long, env = "CF_ACCOUNT_ID")]
    pub account_id: Option<String>,

    /// Filter audit to a specific zone by domain name or 32-character zone ID
    #[arg(short = 'z', long)]
    pub zone: Option<String>,

    /// Run audit offline using built-in synthetic test zones
    #[arg(short = 'm', long)]
    pub mock: bool,

    /// Load zone data from a mock JSON file instead of live API
    #[arg(short = 'i', long)]
    pub input: Option<PathBuf>,

    /// Output report format
    #[arg(short = 'f', long, value_enum, default_value = "table")]
    pub format: OutputFormat,

    /// Write report to a file path instead of stdout
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// CI Compliance Gate: Exit with code 1 if average score is below threshold (0-100)
    #[arg(long)]
    pub min_score: Option<u32>,

    /// CI Compliance Gate: Exit with code 1 if any Critical severity finding is found
    #[arg(long)]
    pub fail_on_critical: bool,

    /// CI Compliance Gate: Exit with code 1 if any High or Critical severity finding is found
    #[arg(long)]
    pub fail_on_high: bool,

    /// CI Compliance Gate: Shorthand for --fail-on-critical --fail-on-high --min-score 80
    #[arg(long)]
    pub check: bool,

    /// Verbose output (includes passed check details)
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Quiet mode (suppresses banners and extraneous output)
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Disable colored terminal output
    #[arg(long)]
    pub no_color: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Html,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RuleListFormat {
    Table,
    Json,
}
