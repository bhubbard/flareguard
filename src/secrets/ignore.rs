use glob::Pattern;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Manages ignore rules, file exclusion patterns, and secret allowlists.
#[derive(Debug, Clone, Default)]
pub struct IgnoreFilter {
    pub ignored_rules: HashSet<String>,
    pub ignored_secrets: HashSet<String>,
    pub file_patterns: Vec<Pattern>,
}

impl IgnoreFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an ignored rule ID (e.g. `CF-006` or `ENV-PORT`).
    pub fn ignore_rule(&mut self, rule_id: &str) {
        self.ignored_rules.insert(rule_id.to_string());
    }

    /// Add an exact secret string or fingerprint to ignore.
    pub fn ignore_secret(&mut self, secret: &str) {
        self.ignored_secrets.insert(secret.to_string());
    }

    /// Add a glob pattern to exclude matching files.
    pub fn add_exclude_pattern(&mut self, pattern_str: &str) -> Result<(), glob::PatternError> {
        let pat = Pattern::new(pattern_str)?;
        self.file_patterns.push(pat);
        Ok(())
    }

    /// Loads rules/patterns from a `.cfsecretignore` file.
    pub fn load_from_file(&mut self, path: &Path) -> Result<(), std::io::Error> {
        if !path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(path)?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(rule) = trimmed.strip_prefix("rule:") {
                self.ignore_rule(rule.trim());
            } else if let Some(secret) = trimmed.strip_prefix("secret:") {
                self.ignore_secret(secret.trim());
            } else {
                // Treat as file glob or secret
                if trimmed.contains('*') || trimmed.contains('?') || trimmed.contains('/') {
                    if let Ok(pat) = Pattern::new(trimmed) {
                        self.file_patterns.push(pat);
                    }
                } else {
                    self.ignore_secret(trimmed);
                }
            }
        }

        Ok(())
    }

    /// Checks if a file path should be ignored.
    pub fn is_file_ignored(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        for pattern in &self.file_patterns {
            if pattern.matches(&path_str) {
                return true;
            }
            if let Some(file_name) = path.file_name().and_then(|f| f.to_str())
                && pattern.matches(file_name)
            {
                return true;
            }
        }
        false
    }

    /// Checks if a rule ID is ignored.
    pub fn is_rule_ignored(&self, rule_id: &str) -> bool {
        self.ignored_rules.contains(rule_id)
    }

    /// Checks if a matched secret value is ignored.
    pub fn is_secret_ignored(&self, secret: &str) -> bool {
        self.ignored_secrets.contains(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_ignore_filter() {
        let mut filter = IgnoreFilter::new();
        filter.ignore_rule("CF-006");
        filter.ignore_secret("0x4AAAAAA_test_safe_dummy");
        filter.add_exclude_pattern("*.map").unwrap();

        assert!(filter.is_rule_ignored("CF-006"));
        assert!(!filter.is_rule_ignored("CF-001"));

        assert!(filter.is_secret_ignored("0x4AAAAAA_test_safe_dummy"));
        assert!(!filter.is_secret_ignored("0x4AAAAAA_real_secret"));

        assert!(filter.is_file_ignored(Path::new("dist/client/app.js.map")));
        assert!(!filter.is_file_ignored(Path::new("dist/client/app.js")));
    }

    #[test]
    fn test_load_ignore_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"
# Ignore configuration
rule: CF-006
*.test.js
secret: safe_known_dummy_token
"#
        )
        .unwrap();

        let mut filter = IgnoreFilter::new();
        filter.load_from_file(tmp.path()).unwrap();

        assert!(filter.is_rule_ignored("CF-006"));
        assert!(filter.is_file_ignored(Path::new("chunk.test.js")));
        assert!(filter.is_secret_ignored("safe_known_dummy_token"));
    }
}
