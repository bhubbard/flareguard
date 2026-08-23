use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use crate::secrets::rules::types::{Rule, Severity};

/// Known non-secret variable keys to ignore when scanning.
const BENIGN_KEYS: &[&str] = &[
    "port", "host", "hostname", "node_env", "env", "environment", "app_env", "stage",
    "debug", "log_level", "tz", "lang", "app_name", "title", "version",
];

/// Known non-secret string values to ignore when scanning for leaked environment variables.
const BENIGN_VALUES: &[&str] = &[
    "true", "false", "null", "undefined", "none", "0", "1", "true\n", "false\n",
    "development", "production", "staging", "test", "local", "dev", "prod",
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "http://localhost", "https://localhost",
    "http://127.0.0.1", "https://127.0.0.1", "http://localhost:8787", "http://localhost:3000",
    "http://localhost:5173", "http://localhost:4321", "public", "index.html",
    "utf-8", "application/json", "text/html", "text/plain", "GET", "POST", "PUT", "DELETE",
    "info", "warn", "warning", "error", "trace", "verbose",
];

/// Represents an extracted environment variable key-value pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvSecret {
    pub key: String,
    pub value: String,
    pub source_file: PathBuf,
}

/// Parses an env-style file (`.env`, `.dev.vars`) into key-value pairs.
pub fn parse_env_file(path: &Path) -> Result<Vec<EnvSecret>, std::io::Error> {
    let content = fs::read_to_string(path)?;
    let mut secrets = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().to_string();
            let mut val = v.trim().to_string();

            // Strip enclosing quotes if present
            if ((val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\'')))
                && val.len() >= 2
            {
                val = val[1..val.len() - 1].to_string();
            }

            // Skip invalid or placeholder values
            if is_secret_candidate(&key, &val) {
                secrets.push(EnvSecret {
                    key,
                    value: val,
                    source_file: path.to_path_buf(),
                });
            }
        }
    }

    Ok(secrets)
}

/// Parses wrangler configuration files (`wrangler.json`, `wrangler.jsonc`, `wrangler.toml`)
pub fn parse_wrangler_file(path: &Path) -> Result<Vec<EnvSecret>, std::io::Error> {
    let content = fs::read_to_string(path)?;
    let mut secrets = Vec::new();

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext == "toml" {
        // Simple TOML [vars] block extractor
        let mut in_vars = false;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_vars = trimmed == "[vars]" || trimmed.starts_with("[env.") && trimmed.ends_with(".vars]");
                continue;
            }

            if in_vars
                && !trimmed.is_empty()
                && !trimmed.starts_with('#')
                && let Some((k, v)) = trimmed.split_once('=')
            {
                let key = k.trim().to_string();
                let mut val = v.trim().to_string();
                if ((val.starts_with('"') && val.ends_with('"'))
                    || (val.starts_with('\'') && val.ends_with('\'')))
                    && val.len() >= 2
                {
                    val = val[1..val.len() - 1].to_string();
                }
                if is_secret_candidate(&key, &val) {
                    secrets.push(EnvSecret {
                        key,
                        value: val,
                        source_file: path.to_path_buf(),
                    });
                }
            }
        }
    } else {
        // JSON or JSONC: strip comments if JSONC then parse
        let cleaned = strip_jsonc_comments(&content);
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&cleaned) {
            extract_secrets_from_json(&val, path, &mut secrets);
        }
    }

    Ok(secrets)
}

fn strip_jsonc_comments(jsonc: &str) -> String {
    let mut result = String::with_capacity(jsonc.len());
    let mut in_string = false;
    let mut chars = jsonc.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '"' && !in_string {
            in_string = true;
            result.push(c);
        } else if c == '"' && in_string {
            in_string = false;
            result.push(c);
        } else if in_string {
            result.push(c);
            if c == '\\' && let Some(next) = chars.next() {
                result.push(next);
            }
        } else if c == '/' && chars.peek() == Some(&'/') {
            // Line comment: skip until newline
            for next in chars.by_ref() {
                if next == '\n' {
                    result.push('\n');
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            // Block comment: skip until */
            chars.next(); // consume '*'
            let mut prev = ' ';
            for next in chars.by_ref() {
                if prev == '*' && next == '/' {
                    break;
                }
                prev = next;
            }
        } else {
            result.push(c);
        }
    }

    result
}

fn extract_secrets_from_json(value: &serde_json::Value, path: &Path, secrets: &mut Vec<EnvSecret>) {
    if let Some(obj) = value.as_object() {
        // Look for vars block or top level
        if let Some(vars) = obj.get("vars").and_then(|v| v.as_object()) {
            for (k, v) in vars {
                if let Some(s) = v.as_str()
                    && is_secret_candidate(k, s)
                {
                    secrets.push(EnvSecret {
                        key: k.clone(),
                        value: s.to_string(),
                        source_file: path.to_path_buf(),
                    });
                }
            }
        }

        // Look for env.*.vars blocks
        if let Some(env_obj) = obj.get("env").and_then(|e| e.as_object()) {
            for (_env_name, env_val) in env_obj {
                if let Some(vars) = env_val.get("vars").and_then(|v| v.as_object()) {
                    for (k, v) in vars {
                        if let Some(s) = v.as_str()
                            && is_secret_candidate(k, s)
                        {
                            secrets.push(EnvSecret {
                                key: k.clone(),
                                value: s.to_string(),
                                source_file: path.to_path_buf(),
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Decides whether a variable key/value should be monitored as a potential secret leak.
pub fn is_secret_candidate(key: &str, value: &str) -> bool {
    let trimmed_val = value.trim();
    let lower_key = key.to_ascii_lowercase();

    // Ignore known benign non-secret variable keys
    if BENIGN_KEYS.contains(&lower_key.as_str()) {
        return false;
    }

    // Ignore short values (< 4 chars) to prevent massive false positive substring matching
    if trimmed_val.len() < 4 {
        return false;
    }

    // Ignore purely numeric values (like ports, IDs, counts)
    if trimmed_val.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Ignore placeholder templates like ${FOO} or $FOO
    if (trimmed_val.starts_with("${") && trimmed_val.ends_with('}'))
        || trimmed_val.starts_with('$')
        || trimmed_val == "<secret>"
        || trimmed_val == "CHANGE_ME"
        || trimmed_val == "your-secret-here"
    {
        return false;
    }

    // Ignore known benign constants
    let lower_val = trimmed_val.to_ascii_lowercase();
    for &benign in BENIGN_VALUES {
        if lower_val == benign {
            return false;
        }
    }

    // Keys explicitly indicating public variables are safe (e.g. PUBLIC_*, NEXT_PUBLIC_*, VITE_PUBLIC_*, ASTRO_PUBLIC_*)
    if lower_key.starts_with("public_")
        || lower_key.starts_with("next_public_")
        || lower_key.starts_with("vite_public_")
        || lower_key.starts_with("astro_public_")
    {
        return false;
    }

    true
}

/// Auto-discovers environment files in search directories and parent directory trees.
pub fn discover_env_files(search_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut discovered = Vec::new();
    let mut seen = HashSet::new();

    let target_names = [
        ".dev.vars",
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        "wrangler.jsonc",
        "wrangler.json",
        "wrangler.toml",
    ];

    let mut check_dirs = Vec::new();

    // Include current working directory
    if let Ok(cwd) = std::env::current_dir() {
        check_dirs.push(cwd);
    }

    for dir in search_dirs {
        let mut curr = if dir.is_file() {
            dir.parent().unwrap_or(Path::new(".")).to_path_buf()
        } else {
            dir.to_path_buf()
        };

        // Walk up to 4 parent directory levels
        for _ in 0..4 {
            check_dirs.push(curr.clone());
            if let Some(parent) = curr.parent() {
                curr = parent.to_path_buf();
            } else {
                break;
            }
        }
    }

    for check_dir in check_dirs {
        for name in &target_names {
            let candidate = check_dir.join(name);
            if candidate.is_file() {
                let canonical = candidate.canonicalize().unwrap_or(candidate.clone());
                if seen.insert(canonical) {
                    discovered.push(candidate);
                }
            }
        }
    }

    discovered
}

/// Converts a collection of `EnvSecret` into detection `Rule`s.
pub fn env_secrets_to_rules(secrets: &[EnvSecret]) -> Vec<Rule> {
    let mut rules = Vec::new();

    for secret in secrets {
        let rule = Rule::new_exact(
            format!("ENV-{}", secret.key),
            format!("Leaked Env Secret ({})", secret.key),
            format!(
                "Secret value for '{}' defined in {} was found in client build asset",
                secret.key,
                secret.source_file.display()
            ),
            Severity::Critical,
            secret.value.clone(),
            format!(
                "Remove references to server variable '{}' from client-side code. Ensure environment variables accessed in client components are prefixed with PUBLIC_ or handled server-side.",
                secret.key
            ),
        );
        rules.push(rule);
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_parse_env_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
# Sample .dev.vars
DATABASE_URL="postgres://postgres:secret123@db.example.com:5432/main"
CLOUDFLARE_API_TOKEN=V48uXZ-e_92mKqT1pLwRtYuIoPsDfGhJkLxZc0vb
PUBLIC_SITE_URL=https://mycoolsite.com
IS_PROD=true
PORT=8787
"#
        )
        .unwrap();

        let secrets = parse_env_file(tmp.path()).unwrap();
        assert_eq!(secrets.len(), 2);

        let keys: Vec<&str> = secrets.iter().map(|s| s.key.as_str()).collect();
        assert!(keys.contains(&"DATABASE_URL"));
        assert!(keys.contains(&"CLOUDFLARE_API_TOKEN"));
        assert!(!keys.contains(&"PUBLIC_SITE_URL"));
        assert!(!keys.contains(&"IS_PROD"));
        assert!(!keys.contains(&"PORT"));
    }

    #[test]
    fn test_parse_wrangler_jsonc() {
        let mut tmp = tempfile::Builder::new().suffix(".jsonc").tempfile().unwrap();
        writeln!(
            tmp,
            r#"
{{
  // Cloudflare Worker configuration
  "name": "my-worker",
  "vars": {{
    "AUTH_SECRET": "super_secret_auth_token_987654321",
    "PUBLIC_API_URL": "https://api.myworker.dev"
  }}
}}
"#
        )
        .unwrap();

        let secrets = parse_wrangler_file(tmp.path()).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].key, "AUTH_SECRET");
        assert_eq!(secrets[0].value, "super_secret_auth_token_987654321");
    }

    #[test]
    fn test_parse_wrangler_toml() {
        let mut tmp = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            tmp,
            r#"
name = "my-worker"
compatibility_date = "2024-01-01"

[vars]
API_SIGNING_KEY = "my_custom_hmac_signing_key_456"
PUBLIC_NAME = "My Public App"
"#
        )
        .unwrap();

        let secrets = parse_wrangler_file(tmp.path()).unwrap();
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].key, "API_SIGNING_KEY");
    }
}
