use regex::Regex;
use crate::secrets::rules::types::{Rule, Severity};

/// Returns all built-in security rules for Cloudflare secret detection.
pub fn get_builtin_rules() -> Vec<Rule> {
    vec![
        // CF-001: Cloudflare API Token (Contextual)
        Rule::new_regex(
            "CF-001",
            "Cloudflare API Token",
            "Detects Cloudflare API Tokens (40-char token) referenced in client bundles",
            Severity::Critical,
            Regex::new(r#"(?i)(?:cloudflare|cf)[-_]?(?:api[-_]?)?token\s*[:=]\s*['"]?([a-zA-Z0-9_-]{40})['"]?"#)
                .expect("Valid regex for CF-001"),
            "Move Cloudflare API Token to server-side environment variables or Cloudflare Workers secrets (wrangler secret put). Never expose API tokens in client-side code.",
        ),

        // CF-002: Cloudflare Global API Key
        Rule::new_regex(
            "CF-002",
            "Cloudflare Global API Key",
            "Detects Cloudflare Global API Keys (37-character hex string) in client bundles",
            Severity::Critical,
            Regex::new(r#"(?i)(?:(?:cloudflare|cf)[-_]?(?:api[-_]?)?key|x-auth-key)\s*[:=]\s*['"]?([a-f0-9]{37})['"]?|\b([a-f0-9]{37})\b"#)
                .expect("Valid regex for CF-002"),
            "Rotate your Cloudflare Global API Key immediately and use scoped, least-privilege API Tokens instead. Never embed Global API Keys in client assets.",
        ),

        // CF-003: Cloudflare Origin CA Key
        Rule::new_regex(
            "CF-003",
            "Cloudflare Origin CA Key",
            "Detects Cloudflare Origin CA Key (v1.0- prefix) in client bundles",
            Severity::Critical,
            Regex::new(r#"\b(v1\.0-[a-zA-Z0-9_\-]{24,128})\b"#)
                .expect("Valid regex for CF-003"),
            "Origin CA keys allow generating certificates for your Cloudflare domains and must be kept strictly server-side.",
        ),

        // CF-004: Cloudflare Turnstile Secret Key
        Rule::new_regex(
            "CF-004",
            "Cloudflare Turnstile Secret Key",
            "Detects Cloudflare Turnstile Secret Key (used for server-side siteverify)",
            Severity::Critical,
            Regex::new(r#"(?i)(?:(?:cf[-_]?)?turnstile[-_]?(?:secret[-_]?key|secret)|(?:turnstile|cf)[-_]?private[-_]?key)\s*[:=]\s*['"]?([0-9a-zA-Z_-]{20,65})['"]?|\b([123]x0000000000000000000000000000000AA)\b"#)
                .expect("Valid regex for CF-004"),
            "Cloudflare Turnstile secret keys (0x4AAAA...) are for server-side verification only (/siteverify). Only publish your public Site Key in client HTML/JS.",
        ),

        // CF-005: Cloudflare Access Service Token Client Secret
        Rule::new_regex(
            "CF-005",
            "Cloudflare Access Service Token Secret",
            "Detects Cloudflare Zero Trust Access Service Token Client Secret",
            Severity::Critical,
            Regex::new(r#"(?i)(?:cf[-_]?access[-_]?client[-_]?secret|CF-Access-Client-Secret)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{32,64})['"]?"#)
                .expect("Valid regex for CF-005"),
            "Access Service Token secrets grant automated access past Cloudflare Zero Trust Access policies. Keep secrets server-side.",
        ),

        // CF-006: Cloudflare Account ID (in secret context)
        Rule::new_regex(
            "CF-006",
            "Cloudflare Account ID in Context",
            "Detects Cloudflare Account ID (32-hex characters) assigned in sensitive configuration contexts",
            Severity::Medium,
            Regex::new(r#"(?i)(?:cloudflare|cf)[-_]?(?:account[-_]?id)\s*[:=]\s*['"]?([a-f0-9]{32})['"]?"#)
                .expect("Valid regex for CF-006"),
            "Avoid leaking Cloudflare Account IDs in client bundles to minimize reconnaissance surface against your Cloudflare account.",
        ),

        // CF-007: Cloudflare R2 / Storage Secret Access Key
        Rule::new_regex(
            "CF-007",
            "Cloudflare R2 / S3 Secret Access Key",
            "Detects Cloudflare R2 or S3-compatible secret access keys (40 characters)",
            Severity::Critical,
            Regex::new(r#"(?i)(?:r2|s3|aws)[-_]?(?:secret[-_]?access[-_]?key|secret[-_]?key)\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?"#)
                .expect("Valid regex for CF-007"),
            "Cloudflare R2 secret access keys provide direct read/write/delete access to buckets. Use Presigned URLs or Worker bindings instead.",
        ),

        // CF-008: Database Connection String / D1 Credentials
        Rule::new_regex(
            "CF-008",
            "Database Connection String / D1 Secret",
            "Detects embedded database connection strings or D1 credentials in client bundles",
            Severity::Critical,
            Regex::new(r#"(?i)\b(?:postgres|postgresql|mysql|redis|mongodb|couchdb|d1):\/\/[^\s:@/]+:[^\s:@]+@[a-zA-Z0-9_.-]+(?::[0-9]+)?(?:\/[^\s'"`;]*)?|\b(?:d1[-_]?(?:token|api[-_]?token|database[-_]?token))\s*[:=]\s*['"]?([a-zA-Z0-9_-]{32,64})['"]?"#)
                .expect("Valid regex for CF-008"),
            "Never expose database credentials or connection strings to client-side browsers. Query databases via backend Worker APIs or Cloudflare Hyperdrive / D1 bindings.",
        ),

        // CF-009: Generic High-Entropy Cloudflare API Token
        Rule::new_regex(
            "CF-009",
            "Standalone High-Entropy Cloudflare API Token",
            "Detects standalone 40-character high-entropy API tokens with Cloudflare token characteristics",
            Severity::High,
            Regex::new(r#"\b([a-zA-Z0-9_-]{40})\b"#)
                .expect("Valid regex for CF-009"),
            "Review if this 40-character high-entropy token is a Cloudflare API token or private service credential.",
        ).with_min_entropy(3.8),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cf_api_token_rule() {
        let rules = get_builtin_rules();
        let cf_token_rule = rules.iter().find(|r| r.id == "CF-001").unwrap();
        let re = cf_token_rule.pattern.as_ref().unwrap();

        let sample = "const CF_API_TOKEN = 'V48uXZ-e_92mKqT1pLwRtYuIoPsDfGhJkLxZc0vb';";
        assert!(re.is_match(sample));

        let sample2 = "CLOUDFLARE_API_TOKEN: \"V48uXZ-e_92mKqT1pLwRtYuIoPsDfGhJkLxZc0vb\"";
        assert!(re.is_match(sample2));
    }

    #[test]
    fn test_cf_global_api_key_rule() {
        let rules = get_builtin_rules();
        let key_rule = rules.iter().find(|r| r.id == "CF-002").unwrap();
        let re = key_rule.pattern.as_ref().unwrap();

        // 37 hex characters
        let sample = "c2547eb745079dac9320b638f5e22594b678a";
        assert_eq!(sample.len(), 37);
        assert!(re.is_match(sample));

        let sample_context = "CF_API_KEY = \"c2547eb745079dac9320b638f5e22594b678a\"";
        assert!(re.is_match(sample_context));
    }

    #[test]
    fn test_origin_ca_key_rule() {
        let rules = get_builtin_rules();
        let origin_rule = rules.iter().find(|r| r.id == "CF-003").unwrap();
        let re = origin_rule.pattern.as_ref().unwrap();

        let sample = "v1.0-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        assert!(re.is_match(sample));
    }

    #[test]
    fn test_turnstile_secret_rule() {
        let rules = get_builtin_rules();
        let turnstile_rule = rules.iter().find(|r| r.id == "CF-004").unwrap();
        let re = turnstile_rule.pattern.as_ref().unwrap();

        let sample1 = "turnstileSecret: '0x4AAAAAAAE-xyz1234567890abcdef'";
        assert!(re.is_match(sample1));

        let sample2 = "TURNSTILE_SECRET_KEY = '0x4AAAAAA1234567890abcdef1234567890'";
        assert!(re.is_match(sample2));

        let sample3 = "1x0000000000000000000000000000000AA";
        assert!(re.is_match(sample3));
    }

    #[test]
    fn test_access_secret_rule() {
        let rules = get_builtin_rules();
        let access_rule = rules.iter().find(|r| r.id == "CF-005").unwrap();
        let re = access_rule.pattern.as_ref().unwrap();

        let sample = "CF_ACCESS_CLIENT_SECRET = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'";
        assert!(re.is_match(sample));
    }

    #[test]
    fn test_db_connection_string_rule() {
        let rules = get_builtin_rules();
        let db_rule = rules.iter().find(|r| r.id == "CF-008").unwrap();
        let re = db_rule.pattern.as_ref().unwrap();

        let sample = "const dbUri = 'postgres://admin:SuperSecretPass123!@db.cloudflare.internal:5432/production';";
        assert!(re.is_match(sample));
    }
}
