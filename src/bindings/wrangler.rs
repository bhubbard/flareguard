use crate::bindings::jsonc::parse_jsonc;
use crate::bindings::types::{BindingType, DeclaredBinding};
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// Locate a wrangler configuration file (`wrangler.jsonc`, `wrangler.json`, `wrangler.toml`).
pub fn find_wrangler_config(start_dir: &Path) -> Option<PathBuf> {
    let candidate_names = ["wrangler.jsonc", "wrangler.json", "wrangler.toml"];
    let mut current = start_dir.to_path_buf();

    for _ in 0..4 {
        for name in &candidate_names {
            let candidate = current.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            break;
        }
    }
    None
}

/// Result of parsing a Wrangler configuration file.
#[derive(Debug, Clone)]
pub struct WranglerConfig {
    pub file_path: PathBuf,
    pub root_bindings: Vec<DeclaredBinding>,
    pub environments: BTreeMap<String, Vec<DeclaredBinding>>,
}

impl WranglerConfig {
    /// Retrieve bindings for a specific environment (inheriting and overriding root bindings).
    pub fn get_bindings_for_env(&self, env_name: Option<&str>) -> Result<Vec<DeclaredBinding>, Box<dyn Error + Send + Sync>> {
        let mut map: HashMap<String, DeclaredBinding> = HashMap::new();

        // Load root bindings first
        for b in &self.root_bindings {
            map.insert(b.name.clone(), b.clone());
        }

        if let Some(env) = env_name {
            if let Some(env_bindings) = self.environments.get(env) {
                for b in env_bindings {
                    map.insert(b.name.clone(), b.clone());
                }
            } else {
                let available: Vec<String> = self.environments.keys().cloned().collect();
                return Err(format!(
                    "Environment '{}' not found in {}. Available environments: {:?}",
                    env,
                    self.file_path.display(),
                    available
                )
                .into());
            }
        }

        let mut list: Vec<DeclaredBinding> = map.into_values().collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(list)
    }
}

/// Parses a wrangler configuration file (TOML, JSON, or JSONC).
pub fn parse_wrangler_config(path: &Path) -> Result<WranglerConfig, Box<dyn Error + Send + Sync>> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read wrangler config {}: {}", path.display(), e))?;
    let path_str = path.to_string_lossy().to_string();

    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext == "toml" {
        parse_wrangler_toml(&content, &path_str, path)
    } else {
        // Assume json or jsonc
        parse_wrangler_json(&content, &path_str, path)
    }
}

/// Parse TOML wrangler configuration
fn parse_wrangler_toml(
    content: &str,
    file_path_str: &str,
    path: &Path,
) -> Result<WranglerConfig, Box<dyn Error + Send + Sync>> {
    let toml_val: toml::Value = toml::from_str(content)
        .map_err(|e| format!("Failed to parse TOML in {}: {}", path.display(), e))?;

    // Convert to serde_json::Value for unified extraction logic
    let json_val: serde_json::Value = serde_json::to_value(toml_val)?;

    extract_wrangler_config_from_json(&json_val, file_path_str, path)
}

/// Parse JSON / JSONC wrangler configuration
fn parse_wrangler_json(
    content: &str,
    file_path_str: &str,
    path: &Path,
) -> Result<WranglerConfig, Box<dyn Error + Send + Sync>> {
    let json_val = parse_jsonc(content)
        .map_err(|e| format!("Failed to parse JSON/JSONC in {}: {}", path.display(), e))?;

    extract_wrangler_config_from_json(&json_val, file_path_str, path)
}

/// Unified extraction from serde_json::Value
fn extract_wrangler_config_from_json(
    val: &serde_json::Value,
    file_path_str: &str,
    path: &Path,
) -> Result<WranglerConfig, Box<dyn Error + Send + Sync>> {
    let root_bindings = extract_bindings_from_object(val, file_path_str, "root");

    let mut environments = BTreeMap::new();
    if let Some(env_map) = val.get("env").and_then(|e| e.as_object()) {
        for (env_name, env_val) in env_map {
            let env_bindings = extract_bindings_from_object(env_val, file_path_str, env_name);
            environments.insert(env_name.clone(), env_bindings);
        }
    }

    Ok(WranglerConfig {
        file_path: path.to_path_buf(),
        root_bindings,
        environments,
    })
}

/// Extract bindings from a single environment or root config object
pub fn extract_bindings_from_object(
    val: &serde_json::Value,
    file_path: &str,
    env_name: &str,
) -> Vec<DeclaredBinding> {
    let mut bindings = Vec::new();
    let obj = match val.as_object() {
        Some(o) => o,
        None => return bindings,
    };

    // 1. vars
    if let Some(vars) = obj.get("vars").and_then(|v| v.as_object()) {
        for (k, v) in vars {
            bindings.push(DeclaredBinding {
                name: k.clone(),
                binding_type: BindingType::Var,
                file: file_path.to_string(),
                environment: env_name.to_string(),
                details: Some(format!("value: {}", v)),
            });
        }
    }

    // 2. kv_namespaces
    if let Some(kvs) = obj.get("kv_namespaces").and_then(|k| k.as_array()) {
        for kv in kvs {
            if let Some(binding) = kv.get("binding").and_then(|b| b.as_str()) {
                let id = kv.get("id").and_then(|i| i.as_str()).map(|s| format!("id: {}", s));
                bindings.push(DeclaredBinding {
                    name: binding.to_string(),
                    binding_type: BindingType::KvNamespace,
                    file: file_path.to_string(),
                    environment: env_name.to_string(),
                    details: id,
                });
            }
        }
    }

    // 3. d1_databases
    if let Some(d1s) = obj.get("d1_databases").and_then(|d| d.as_array()) {
        for d1 in d1s {
            if let Some(binding) = d1.get("binding").and_then(|b| b.as_str()) {
                let db_name = d1.get("database_name").and_then(|n| n.as_str()).map(|s| format!("db: {}", s));
                bindings.push(DeclaredBinding {
                    name: binding.to_string(),
                    binding_type: BindingType::D1Database,
                    file: file_path.to_string(),
                    environment: env_name.to_string(),
                    details: db_name,
                });
            }
        }
    }

    // 4. r2_buckets
    if let Some(r2s) = obj.get("r2_buckets").and_then(|r| r.as_array()) {
        for r2 in r2s {
            if let Some(binding) = r2.get("binding").and_then(|b| b.as_str()) {
                let bucket = r2.get("bucket_name").and_then(|n| n.as_str()).map(|s| format!("bucket: {}", s));
                bindings.push(DeclaredBinding {
                    name: binding.to_string(),
                    binding_type: BindingType::R2Bucket,
                    file: file_path.to_string(),
                    environment: env_name.to_string(),
                    details: bucket,
                });
            }
        }
    }

    // 5. vectorize
    if let Some(vecs) = obj.get("vectorize") {
        if let Some(arr) = vecs.as_array() {
            for v in arr {
                if let Some(binding) = v.get("binding").and_then(|b| b.as_str()) {
                    let idx = v.get("index_name").and_then(|n| n.as_str()).map(|s| format!("index: {}", s));
                    bindings.push(DeclaredBinding {
                        name: binding.to_string(),
                        binding_type: BindingType::Vectorize,
                        file: file_path.to_string(),
                        environment: env_name.to_string(),
                        details: idx,
                    });
                }
            }
        } else if let Some(v_obj) = vecs.as_object() {
            if let Some(binding) = v_obj.get("binding").and_then(|b| b.as_str()) {
                let idx = v_obj.get("index_name").and_then(|n| n.as_str()).map(|s| format!("index: {}", s));
                bindings.push(DeclaredBinding {
                    name: binding.to_string(),
                    binding_type: BindingType::Vectorize,
                    file: file_path.to_string(),
                    environment: env_name.to_string(),
                    details: idx,
                });
            }
        }
    }

    // 6. hyperdrive
    if let Some(hds) = obj.get("hyperdrive").and_then(|h| h.as_array()) {
        for hd in hds {
            if let Some(binding) = hd.get("binding").and_then(|b| b.as_str()) {
                let id = hd.get("id").and_then(|i| i.as_str()).map(|s| format!("id: {}", s));
                bindings.push(DeclaredBinding {
                    name: binding.to_string(),
                    binding_type: BindingType::Hyperdrive,
                    file: file_path.to_string(),
                    environment: env_name.to_string(),
                    details: id,
                });
            }
        }
    }

    // 7. services
    if let Some(services) = obj.get("services").and_then(|s| s.as_array()) {
        for s in services {
            if let Some(binding) = s.get("binding").and_then(|b| b.as_str()) {
                let svc = s.get("service").and_then(|n| n.as_str()).map(|srv| format!("service: {}", srv));
                bindings.push(DeclaredBinding {
                    name: binding.to_string(),
                    binding_type: BindingType::Service,
                    file: file_path.to_string(),
                    environment: env_name.to_string(),
                    details: svc,
                });
            }
        }
    }

    // 8. analytics_engine_datasets
    if let Some(aeds) = obj.get("analytics_engine_datasets").and_then(|a| a.as_array()) {
        for a in aeds {
            if let Some(binding) = a.get("binding").and_then(|b| b.as_str()) {
                let ds = a.get("dataset").and_then(|d| d.as_str()).map(|s| format!("dataset: {}", s));
                bindings.push(DeclaredBinding {
                    name: binding.to_string(),
                    binding_type: BindingType::AnalyticsEngine,
                    file: file_path.to_string(),
                    environment: env_name.to_string(),
                    details: ds,
                });
            }
        }
    }

    // 9. durable_objects
    if let Some(do_val) = obj.get("durable_objects").and_then(|d| d.as_object()) {
        if let Some(bindings_arr) = do_val.get("bindings").and_then(|b| b.as_array()) {
            for b in bindings_arr {
                let name = b.get("name").or_else(|| b.get("binding")).and_then(|n| n.as_str());
                if let Some(binding_name) = name {
                    let cls = b.get("class_name").and_then(|c| c.as_str()).map(|s| format!("class: {}", s));
                    bindings.push(DeclaredBinding {
                        name: binding_name.to_string(),
                        binding_type: BindingType::DurableObject,
                        file: file_path.to_string(),
                        environment: env_name.to_string(),
                        details: cls,
                    });
                }
            }
        }
    }

    // 10. queues (producers)
    if let Some(queues) = obj.get("queues").and_then(|q| q.as_object()) {
        if let Some(producers) = queues.get("producers").and_then(|p| p.as_array()) {
            for p in producers {
                if let Some(binding) = p.get("binding").and_then(|b| b.as_str()) {
                    let q_name = p.get("queue").and_then(|q| q.as_str()).map(|s| format!("queue: {}", s));
                    bindings.push(DeclaredBinding {
                        name: binding.to_string(),
                        binding_type: BindingType::QueueProducer,
                        file: file_path.to_string(),
                        environment: env_name.to_string(),
                        details: q_name,
                    });
                }
            }
        }
    }

    // 11. workflows
    if let Some(wfs) = obj.get("workflows").and_then(|w| w.as_array()) {
        for wf in wfs {
            let name = wf.get("binding").or_else(|| wf.get("name")).and_then(|n| n.as_str());
            if let Some(binding_name) = name {
                let cls = wf.get("class_name").and_then(|c| c.as_str()).map(|s| format!("class: {}", s));
                bindings.push(DeclaredBinding {
                    name: binding_name.to_string(),
                    binding_type: BindingType::Workflow,
                    file: file_path.to_string(),
                    environment: env_name.to_string(),
                    details: cls,
                });
            }
        }
    }

    // 12. ai
    if let Some(ai_val) = obj.get("ai") {
        let binding_name = if let Some(ai_obj) = ai_val.as_object() {
            ai_obj.get("binding").and_then(|b| b.as_str()).unwrap_or("AI")
        } else {
            "AI"
        };
        bindings.push(DeclaredBinding {
            name: binding_name.to_string(),
            binding_type: BindingType::Ai,
            file: file_path.to_string(),
            environment: env_name.to_string(),
            details: None,
        });
    }

    // 13. browser
    if let Some(browser_val) = obj.get("browser") {
        let binding_name = if let Some(b_obj) = browser_val.as_object() {
            b_obj.get("binding").and_then(|b| b.as_str()).unwrap_or("MYBROWSER")
        } else {
            "BROWSER"
        };
        bindings.push(DeclaredBinding {
            name: binding_name.to_string(),
            binding_type: BindingType::Browser,
            file: file_path.to_string(),
            environment: env_name.to_string(),
            details: None,
        });
    }

    // 14. send_email
    if let Some(email_val) = obj.get("send_email") {
        if let Some(arr) = email_val.as_array() {
            for em in arr {
                let name = em.get("name").or_else(|| em.get("binding")).and_then(|n| n.as_str());
                if let Some(binding_name) = name {
                    bindings.push(DeclaredBinding {
                        name: binding_name.to_string(),
                        binding_type: BindingType::SendEmail,
                        file: file_path.to_string(),
                        environment: env_name.to_string(),
                        details: None,
                    });
                }
            }
        } else if let Some(em_obj) = email_val.as_object() {
            let name = em_obj.get("name").or_else(|| em_obj.get("binding")).and_then(|n| n.as_str());
            if let Some(binding_name) = name {
                bindings.push(DeclaredBinding {
                    name: binding_name.to_string(),
                    binding_type: BindingType::SendEmail,
                    file: file_path.to_string(),
                    environment: env_name.to_string(),
                    details: None,
                });
            }
        }
    }

    // 15. mtls_certificates
    if let Some(mtls) = obj.get("mtls_certificates").and_then(|m| m.as_array()) {
        for cert in mtls {
            if let Some(binding) = cert.get("binding").and_then(|b| b.as_str()) {
                let cert_id = cert.get("certificate_id").and_then(|i| i.as_str()).map(|s| format!("cert: {}", s));
                bindings.push(DeclaredBinding {
                    name: binding.to_string(),
                    binding_type: BindingType::MtlsCertificate,
                    file: file_path.to_string(),
                    environment: env_name.to_string(),
                    details: cert_id,
                });
            }
        }
    }

    // 16. pipelines
    if let Some(pipes) = obj.get("pipelines").and_then(|p| p.as_array()) {
        for pipe in pipes {
            if let Some(binding) = pipe.get("binding").and_then(|b| b.as_str()) {
                let p_name = pipe.get("pipeline").and_then(|n| n.as_str()).map(|s| format!("pipeline: {}", s));
                bindings.push(DeclaredBinding {
                    name: binding.to_string(),
                    binding_type: BindingType::Pipeline,
                    file: file_path.to_string(),
                    environment: env_name.to_string(),
                    details: p_name,
                });
            }
        }
    }

    // 17. assets
    if let Some(assets_val) = obj.get("assets").and_then(|a| a.as_object()) {
        if let Some(binding) = assets_val.get("binding").and_then(|b| b.as_str()) {
            let dir = assets_val.get("directory").and_then(|d| d.as_str()).map(|s| format!("dir: {}", s));
            bindings.push(DeclaredBinding {
                name: binding.to_string(),
                binding_type: BindingType::Assets,
                file: file_path.to_string(),
                environment: env_name.to_string(),
                details: dir,
            });
        }
    }

    // 18. secrets (if defined as array of secret names)
    if let Some(secrets) = obj.get("secrets").and_then(|s| s.as_array()) {
        for s in secrets {
            if let Some(name) = s.as_str() {
                bindings.push(DeclaredBinding {
                    name: name.to_string(),
                    binding_type: BindingType::Secret,
                    file: file_path.to_string(),
                    environment: env_name.to_string(),
                    details: None,
                });
            }
        }
    }

    bindings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wrangler_jsonc_all_bindings() {
        let jsonc = r#"
        {
            "name": "full-worker",
            "vars": {
                "API_KEY": "secret123",
                "ENV": "production"
            },
            "kv_namespaces": [
                { "binding": "MY_KV", "id": "kv123" }
            ],
            "d1_databases": [
                { "binding": "DB", "database_name": "prod-db", "database_id": "d1-123" }
            ],
            "r2_buckets": [
                { "binding": "BUCKET", "bucket_name": "my-bucket" }
            ],
            "ai": { "binding": "AI" },
            "browser": { "binding": "HEADLESS" },
            "durable_objects": {
                "bindings": [
                    { "name": "RATE_LIMITER", "class_name": "RateLimiter" }
                ]
            },
            "queues": {
                "producers": [
                    { "binding": "NOTIFY_QUEUE", "queue": "notifications" }
                ]
            },
            "services": [
                { "binding": "AUTH_SVC", "service": "auth-worker" }
            ],
            "vectorize": [
                { "binding": "DOC_INDEX", "index_name": "docs" }
            ],
            "hyperdrive": [
                { "binding": "POSTGRES", "id": "hd123" }
            ],
            "analytics_engine_datasets": [
                { "binding": "METRICS", "dataset": "telemetry" }
            ],
            "workflows": [
                { "name": "ONBOARDING", "class_name": "OnboardingWorkflow" }
            ],
            "env": {
                "staging": {
                    "vars": {
                        "ENV": "staging",
                        "STAGING_FLAG": "true"
                    },
                    "kv_namespaces": [
                        { "binding": "STAGE_KV", "id": "kv-stage" }
                    ]
                }
            }
        }
        "#;
        let config = parse_wrangler_json(jsonc, "wrangler.jsonc", Path::new("wrangler.jsonc")).unwrap();
        let root_bindings = config.get_bindings_for_env(None).unwrap();
        let names: Vec<&str> = root_bindings.iter().map(|b| b.name.as_str()).collect();

        assert!(names.contains(&"API_KEY"));
        assert!(names.contains(&"MY_KV"));
        assert!(names.contains(&"DB"));
        assert!(names.contains(&"BUCKET"));
        assert!(names.contains(&"AI"));
        assert!(names.contains(&"HEADLESS"));
        assert!(names.contains(&"RATE_LIMITER"));
        assert!(names.contains(&"NOTIFY_QUEUE"));
        assert!(names.contains(&"AUTH_SVC"));
        assert!(names.contains(&"DOC_INDEX"));
        assert!(names.contains(&"POSTGRES"));
        assert!(names.contains(&"METRICS"));
        assert!(names.contains(&"ONBOARDING"));

        // Check staging env overrides & inheritance
        let staging_bindings = config.get_bindings_for_env(Some("staging")).unwrap();
        let staging_names: Vec<&str> = staging_bindings.iter().map(|b| b.name.as_str()).collect();
        assert!(staging_names.contains(&"STAGING_FLAG"));
        assert!(staging_names.contains(&"STAGE_KV"));
        assert!(staging_names.contains(&"MY_KV")); // Inherited
    }

    #[test]
    fn test_parse_wrangler_toml() {
        let toml_str = r#"
        name = "toml-worker"

        [vars]
        API_SECRET = "abc"

        [[kv_namespaces]]
        binding = "KV_DATA"
        id = "kv-data-id"

        [[d1_databases]]
        binding = "D1_MAIN"
        database_name = "d1-main"

        [env.preview]
        vars = { PREVIEW_ONLY = "yes" }
        "#;
        let config = parse_wrangler_toml(toml_str, "wrangler.toml", Path::new("wrangler.toml")).unwrap();
        let root_bindings = config.get_bindings_for_env(None).unwrap();
        let names: Vec<&str> = root_bindings.iter().map(|b| b.name.as_str()).collect();
        assert!(names.contains(&"API_SECRET"));
        assert!(names.contains(&"KV_DATA"));
        assert!(names.contains(&"D1_MAIN"));

        let preview_bindings = config.get_bindings_for_env(Some("preview")).unwrap();
        let preview_names: Vec<&str> = preview_bindings.iter().map(|b| b.name.as_str()).collect();
        assert!(preview_names.contains(&"PREVIEW_ONLY"));
        assert!(preview_names.contains(&"API_SECRET"));
    }
}
