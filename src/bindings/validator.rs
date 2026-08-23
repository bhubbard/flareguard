use crate::bindings::ast_scanner::scan_source_file;
use crate::bindings::types::{BindingAccess, DeclaredBinding, ValidationReport, ValidBindingInfo};
use crate::bindings::wrangler::WranglerConfig;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::PathBuf;
use walkdir::WalkDir;

/// Configuration options for the validator.
#[derive(Debug, Clone)]
pub struct ValidatorOptions {
    pub target_paths: Vec<PathBuf>,
    pub environment: Option<String>,
    pub ignore_unused: HashSet<String>,
    pub ignore_undeclared: HashSet<String>,
    pub strict: bool,
}

impl Default for ValidatorOptions {
    fn default() -> Self {
        Self {
            target_paths: vec![PathBuf::from(".")],
            environment: None,
            ignore_unused: HashSet::new(),
            ignore_undeclared: HashSet::new(),
            strict: false,
        }
    }
}

/// Discovers all candidate source files in the given paths.
pub fn discover_source_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let ignored_dirs = [
        "node_modules",
        ".git",
        "target",
        "dist",
        "build",
        ".wrangler",
        ".next",
        ".astro",
        ".cache",
        "coverage",
        ".output",
        "vendor",
        ".turbo",
        ".svelte-kit",
    ];

    let supported_exts = ["ts", "tsx", "js", "jsx", "mjs", "cjs", "astro"];

    for p in paths {
        if p.is_file() {
            if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if supported_exts.contains(&ext) {
                    files.push(p.clone());
                }
            }
            continue;
        }

        if p.is_dir() {
            for entry in WalkDir::new(p)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    let name = e.file_name().to_string_lossy();
                    if e.file_type().is_dir() {
                        !ignored_dirs.contains(&name.as_ref())
                    } else {
                        true
                    }
                })
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    let path = entry.path();
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if supported_exts.contains(&ext) {
                            files.push(path.to_path_buf());
                        }
                    }
                }
            }
        }
    }

    files.sort();
    files
}

/// Runs validation of code binding accesses against declared Wrangler bindings.
pub fn validate_project(
    wrangler_config: Option<&WranglerConfig>,
    options: &ValidatorOptions,
) -> Result<ValidationReport, Box<dyn Error + Send + Sync>> {
    let env_name = options.environment.as_deref().unwrap_or("root");

    // 1. Get declared bindings from Wrangler config
    let declared_bindings = if let Some(cfg) = wrangler_config {
        cfg.get_bindings_for_env(options.environment.as_deref())?
    } else {
        Vec::new()
    };

    let declared_map: HashMap<String, DeclaredBinding> = declared_bindings
        .iter()
        .map(|b| (b.name.clone(), b.clone()))
        .collect();

    // 2. Discover and scan source files
    let source_files = discover_source_files(&options.target_paths);
    let mut all_accesses = Vec::new();

    for file_path in &source_files {
        if let Ok(accesses) = scan_source_file(file_path) {
            all_accesses.extend(accesses);
        }
    }

    // 3. Group accesses by binding name
    let mut accesses_by_name: HashMap<String, Vec<BindingAccess>> = HashMap::new();
    for access in all_accesses.clone() {
        accesses_by_name
            .entry(access.name.clone())
            .or_default()
            .push(access);
    }

    // 4. Cross-reference
    let mut undeclared_accesses = Vec::new();
    let mut ghost_bindings = Vec::new();
    let mut valid_bindings = Vec::new();

    // Check accesses for undeclared bindings
    for (name, accesses) in &accesses_by_name {
        if options.ignore_undeclared.contains(name) {
            continue;
        }

        if !declared_map.contains_key(name) {
            // All accesses to this undeclared name are errors
            undeclared_accesses.extend(accesses.clone());
        }
    }

    // Check declared bindings for unused (ghost) bindings
    for declared in &declared_bindings {
        if options.ignore_unused.contains(&declared.name) {
            continue;
        }

        if let Some(accesses) = accesses_by_name.get(&declared.name) {
            valid_bindings.push(ValidBindingInfo {
                binding: declared.clone(),
                access_count: accesses.len(),
                accesses: accesses.clone(),
            });
        } else {
            // Declared but never accessed in any scanned source file
            ghost_bindings.push(declared.clone());
        }
    }

    // Sort for deterministic results
    undeclared_accesses.sort_by(|a, b| (&a.file_path, a.line, a.column).cmp(&(&b.file_path, b.line, b.column)));
    ghost_bindings.sort_by(|a, b| a.name.cmp(&b.name));
    valid_bindings.sort_by(|a, b| a.binding.name.cmp(&b.binding.name));

    let is_success = if options.strict {
        undeclared_accesses.is_empty() && ghost_bindings.is_empty()
    } else {
        undeclared_accesses.is_empty()
    };

    Ok(ValidationReport {
        config_file: wrangler_config.map(|c| c.file_path.to_string_lossy().to_string()),
        environment: env_name.to_string(),
        total_files_scanned: source_files.len(),
        total_declared: declared_bindings.len(),
        total_accesses: all_accesses.len(),
        undeclared_accesses,
        ghost_bindings,
        valid_bindings,
        is_success,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::types::BindingType;

    #[test]
    fn test_cross_referencing_logic() {
        let root_bindings = vec![
            DeclaredBinding {
                name: "MY_KV".to_string(),
                binding_type: BindingType::KvNamespace,
                file: "wrangler.jsonc".to_string(),
                environment: "root".to_string(),
                details: None,
            },
            DeclaredBinding {
                name: "UNUSED_GHOST_DB".to_string(),
                binding_type: BindingType::D1Database,
                file: "wrangler.jsonc".to_string(),
                environment: "root".to_string(),
                details: None,
            },
        ];

        let config = WranglerConfig {
            file_path: PathBuf::from("wrangler.jsonc"),
            root_bindings,
            environments: std::collections::BTreeMap::new(),
        };

        let mut opts = ValidatorOptions::default();
        opts.target_paths = vec![];

        let report = validate_project(Some(&config), &opts).unwrap();
        assert_eq!(report.ghost_bindings.len(), 2);
    }
}
