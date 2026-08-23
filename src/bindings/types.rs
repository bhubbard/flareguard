use serde::{Deserialize, Serialize};
use std::fmt;

/// The type of Cloudflare Worker/Pages binding declared in Wrangler configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingType {
    KvNamespace,
    D1Database,
    R2Bucket,
    QueueProducer,
    QueueConsumer,
    Vectorize,
    Hyperdrive,
    Ai,
    Service,
    AnalyticsEngine,
    DurableObject,
    Workflow,
    Browser,
    SendEmail,
    MtlsCertificate,
    Pipeline,
    Assets,
    Var,
    Secret,
    Unknown(String),
}

impl fmt::Display for BindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindingType::KvNamespace => write!(f, "KV Namespace"),
            BindingType::D1Database => write!(f, "D1 Database"),
            BindingType::R2Bucket => write!(f, "R2 Bucket"),
            BindingType::QueueProducer => write!(f, "Queue Producer"),
            BindingType::QueueConsumer => write!(f, "Queue Consumer"),
            BindingType::Vectorize => write!(f, "Vectorize Index"),
            BindingType::Hyperdrive => write!(f, "Hyperdrive"),
            BindingType::Ai => write!(f, "Workers AI"),
            BindingType::Service => write!(f, "Service Binding"),
            BindingType::AnalyticsEngine => write!(f, "Analytics Engine Dataset"),
            BindingType::DurableObject => write!(f, "Durable Object"),
            BindingType::Workflow => write!(f, "Workflow"),
            BindingType::Browser => write!(f, "Browser Rendering"),
            BindingType::SendEmail => write!(f, "Send Email"),
            BindingType::MtlsCertificate => write!(f, "mTLS Certificate"),
            BindingType::Pipeline => write!(f, "Pipeline"),
            BindingType::Assets => write!(f, "Static Assets"),
            BindingType::Var => write!(f, "Environment Variable (var)"),
            BindingType::Secret => write!(f, "Secret"),
            BindingType::Unknown(name) => write!(f, "Custom ({})", name),
        }
    }
}

/// A binding declared in `wrangler.jsonc`, `wrangler.json`, or `wrangler.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredBinding {
    pub name: String,
    pub binding_type: BindingType,
    pub file: String,
    pub environment: String,
    pub details: Option<String>,
}

/// How a binding was accessed in source code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessKind {
    DirectMember,
    Destructured,
    ParamDestructured,
    HelperCall,
    ProcessEnv,
}

impl fmt::Display for AccessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessKind::DirectMember => write!(f, "property access"),
            AccessKind::Destructured => write!(f, "destructuring"),
            AccessKind::ParamDestructured => write!(f, "parameter destructuring"),
            AccessKind::HelperCall => write!(f, "helper call"),
            AccessKind::ProcessEnv => write!(f, "process.env access"),
        }
    }
}

/// An instance in source code where a binding was accessed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingAccess {
    pub name: String,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub raw_expression: String,
    pub access_kind: AccessKind,
}

/// Information about a binding that was successfully matched between config and code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidBindingInfo {
    pub binding: DeclaredBinding,
    pub access_count: usize,
    pub accesses: Vec<BindingAccess>,
}

/// Complete report of the validation process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub config_file: Option<String>,
    pub environment: String,
    pub total_files_scanned: usize,
    pub total_declared: usize,
    pub total_accesses: usize,
    pub undeclared_accesses: Vec<BindingAccess>,
    pub ghost_bindings: Vec<DeclaredBinding>,
    pub valid_bindings: Vec<ValidBindingInfo>,
    pub is_success: bool,
}

/// Output formats supported by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}
