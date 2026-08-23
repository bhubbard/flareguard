use crate::origin::error::Result;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct CrtShEntry {
    pub issuer_ca_id: Option<i64>,
    pub issuer_name: Option<String>,
    pub common_name: Option<String>,
    pub name_value: Option<String>,
    pub id: Option<i64>,
    pub entry_timestamp: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub serial_number: Option<String>,
}

/// Parses certificate transparency log entries to extract unique subdomains
pub fn extract_subdomains_from_crtsh(entries: &[CrtShEntry], root_domain: &str) -> Vec<String> {
    let mut subdomains = HashSet::new();
    let root_lower = root_domain
        .to_lowercase()
        .trim_start_matches('.')
        .to_string();

    for entry in entries {
        if let Some(ref common_name) = entry.common_name {
            for line in common_name.lines() {
                clean_and_insert_domain(line, &root_lower, &mut subdomains);
            }
        }
        if let Some(ref name_value) = entry.name_value {
            for line in name_value.lines() {
                clean_and_insert_domain(line, &root_lower, &mut subdomains);
            }
        }
    }

    let mut result: Vec<String> = subdomains.into_iter().collect();
    result.sort();
    result
}

fn clean_and_insert_domain(raw: &str, root_domain: &str, set: &mut HashSet<String>) {
    let trimmed = raw
        .trim()
        .to_lowercase()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .to_string();

    if trimmed.is_empty() {
        return;
    }

    // Must end with root domain or equal root domain
    if trimmed == root_domain || trimmed.ends_with(&format!(".{}", root_domain)) {
        set.insert(trimmed);
    }
}

/// Fetches Certificate Transparency logs for a domain from crt.sh
pub async fn query_crtsh(client: &Client, domain: &str, timeout_secs: u64) -> Result<Vec<String>> {
    let root = domain.trim_start_matches('.').to_lowercase();
    let url = format!("https://crt.sh/?q=%25.{}&output=json", root);

    let response = client
        .get(&url)
        .header("User-Agent", "cf-origin-hunter/0.1.0")
        .timeout(Duration::from_secs(timeout_secs))
        .send()
        .await;

    match response {
        Ok(resp) => {
            if !resp.status().is_success() {
                return Ok(Vec::new());
            }

            let text = resp.text().await.unwrap_or_default();
            if text.trim().is_empty() || text.starts_with('<') {
                return Ok(Vec::new());
            }

            match serde_json::from_str::<Vec<CrtShEntry>>(&text) {
                Ok(entries) => Ok(extract_subdomains_from_crtsh(&entries, &root)),
                Err(_) => Ok(Vec::new()),
            }
        }
        Err(e) => {
            // crt.sh can be intermittently slow or rate-limited; gracefully return empty list
            log_or_ignore(&format!("crt.sh query failed: {}", e));
            Ok(Vec::new())
        }
    }
}

fn log_or_ignore(_msg: &str) {
    // Debug logging if enabled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_subdomains_from_crtsh() {
        let entries = vec![
            CrtShEntry {
                issuer_ca_id: Some(1),
                issuer_name: Some("Let's Encrypt".into()),
                common_name: Some("origin.example.com".into()),
                name_value: Some(
                    "origin.example.com\n*.dev.example.com\napi-origin.example.com".into(),
                ),
                id: Some(100),
                entry_timestamp: None,
                not_before: None,
                not_after: None,
                serial_number: None,
            },
            CrtShEntry {
                issuer_ca_id: Some(2),
                issuer_name: Some("DigiCert".into()),
                common_name: Some("example.com".into()),
                name_value: Some("example.com\notherdomain.com".into()),
                id: Some(101),
                entry_timestamp: None,
                not_before: None,
                not_after: None,
                serial_number: None,
            },
        ];

        let subs = extract_subdomains_from_crtsh(&entries, "example.com");
        assert!(subs.contains(&"origin.example.com".to_string()));
        assert!(subs.contains(&"dev.example.com".to_string()));
        assert!(subs.contains(&"api-origin.example.com".to_string()));
        assert!(subs.contains(&"example.com".to_string()));
        assert!(!subs.contains(&"otherdomain.com".to_string()));
    }
}
