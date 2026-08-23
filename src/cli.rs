use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use std::path::PathBuf;

/// 🛡️ Flareguard — Unified Cloudflare Security & Architecture Guardian
///
/// High-performance Rust CLI & library providing AST secret scanning,
/// Worker binding verification, Zone security posture auditing, and origin IP leak hunting.
#[derive(Parser, Debug)]
#[command(
    name = "flareguard",
    author = "Brandon Hubbard <bhubbard@users.noreply.github.com>",
    version = env!("CARGO_PKG_VERSION"),
    about = "🛡️ Flareguard — Unified Cloudflare Security & Architecture Guardian",
    long_about = "Flareguard brings all Cloudflare security checks into one high-performance tool:\n\
- secrets: Scan code and static bundles for exposed Cloudflare tokens and credentials\n\
- bindings: Validate wrangler.toml/jsonc bindings against JavaScript/TypeScript AST usage\n\
- zone: Audit live Cloudflare Zone security posture (SSL, HSTS, WAF, Bot Fight, DNSSEC)\n\
- origin: Hunt for unmasked backend origin IPs bypassing Cloudflare proxies\n\
- check: Run end-to-end local repository verification (secrets + bindings)\n\
- completions: Generate shell autocompletions (bash, zsh, fish, powershell)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// 🔑 Scan files and bundles for leaked Cloudflare secrets, API tokens, and credentials
    Secrets(crate::secrets::cli::Cli),

    /// ⚡ Validate Cloudflare Worker/Pages bindings against Wrangler configuration and JS/TS ASTs
    Bindings(crate::bindings::cli::CliArgs),

    /// 🌐 Audit Cloudflare Zone security posture, WAF rules, and compliance gates
    Zone(crate::zone::cli::AuditArgs),

    /// 🎯 Hunt for unmasked backend origin IPs behind Cloudflare proxies
    Origin(crate::origin::cli::Cli),

    /// 🚀 Run comprehensive workspace verification (secrets scan + binding validation)
    Check(CheckArgs),

    /// 🐚 Generate shell autocompletion scripts
    Completions {
        /// The target shell
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CheckOutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Args, Debug, Clone)]
pub struct CheckArgs {
    /// Target directory to check (defaults to current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Fail with exit code 1 if any issues are detected
    #[arg(long, default_value_t = true)]
    pub strict: bool,

    /// Output report format (text, json, sarif)
    #[arg(short = 'f', long = "format", value_enum, default_value_t = CheckOutputFormat::Text)]
    pub format: CheckOutputFormat,

    /// Save output report to specified file path
    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,
}
