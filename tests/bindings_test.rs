use flareguard::bindings::reporter::render_report;
use flareguard::bindings::types::OutputFormat;
use flareguard::bindings::validator::{validate_project, ValidatorOptions};
use flareguard::bindings::wrangler::parse_wrangler_config;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

fn create_temp_test_project(test_name: &str) -> PathBuf {
    let base_dir = std::env::temp_dir().join(format!("cf_test_{}_{}", test_name, std::process::id()));
    if base_dir.exists() {
        let _ = fs::remove_dir_all(&base_dir);
    }
    fs::create_dir_all(&base_dir).unwrap();
    base_dir
}

#[test]
fn test_integration_full_valid_project() {
    let temp_dir = create_temp_test_project("valid_proj");

    let wrangler_jsonc = r#"
    {
        "name": "valid-worker",
        "vars": {
            "API_URL": "https://api.example.com",
            "DEBUG_MODE": "false"
        },
        "kv_namespaces": [
            { "binding": "SESSION_STORE", "id": "kv123" }
        ],
        "d1_databases": [
            { "binding": "PRIMARY_DB", "database_name": "users-db" }
        ],
        "r2_buckets": [
            { "binding": "MEDIA_BUCKET", "bucket_name": "media" }
        ],
        "ai": { "binding": "AI" },
        "queues": {
            "producers": [
                { "binding": "EMAIL_QUEUE", "queue": "emails" }
            ]
        }
    }
    "#;

    let worker_ts = r#"
    import { Hono } from 'hono';

    const app = new Hono();

    app.get('/api/media', async (c) => {
        const url = c.env.API_URL;
        const bucket = c.env.MEDIA_BUCKET;
        const db = c.env.PRIMARY_DB;
        const session = c.env.SESSION_STORE;
        const debug = c.env.DEBUG_MODE;
        const ai = c.env.AI;
        const queue = c.env.EMAIL_QUEUE;
        return c.text("ok");
    });

    export default app;
    "#;

    let config_path = temp_dir.join("wrangler.jsonc");
    let src_dir = temp_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let source_path = src_dir.join("index.ts");

    fs::write(&config_path, wrangler_jsonc).unwrap();
    fs::write(&source_path, worker_ts).unwrap();

    let wrangler_config = parse_wrangler_config(&config_path).unwrap();
    let options = ValidatorOptions {
        target_paths: vec![temp_dir.clone()],
        environment: None,
        ignore_unused: HashSet::new(),
        ignore_undeclared: HashSet::new(),
        strict: true,
    };

    let report = validate_project(Some(&wrangler_config), &options).unwrap();

    assert!(report.is_success, "Expected validation to succeed");
    assert_eq!(report.undeclared_accesses.len(), 0, "No undeclared bindings should exist");
    assert_eq!(report.ghost_bindings.len(), 0, "No ghost bindings should exist");
    assert_eq!(report.valid_bindings.len(), 7, "All 7 declared bindings should be matched");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_integration_undeclared_bindings_error() {
    let temp_dir = create_temp_test_project("undeclared_proj");

    let wrangler_toml = r#"
    name = "undeclared-worker"

    [vars]
    EXISTING_VAR = "hello"
    "#;

    let worker_ts = r#"
    export default {
        async fetch(request, env, ctx) {
            // Existing binding
            const v = env.EXISTING_VAR;

            // Undeclared bindings!
            const undeclaredKv = env.MISSING_KV;
            const undeclaredDb = env.NON_EXISTENT_DB;

            return new Response("ok");
        }
    };
    "#;

    let config_path = temp_dir.join("wrangler.toml");
    let src_dir = temp_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let source_path = src_dir.join("worker.ts");

    fs::write(&config_path, wrangler_toml).unwrap();
    fs::write(&source_path, worker_ts).unwrap();

    let wrangler_config = parse_wrangler_config(&config_path).unwrap();
    let options = ValidatorOptions {
        target_paths: vec![temp_dir.clone()],
        environment: None,
        ignore_unused: HashSet::new(),
        ignore_undeclared: HashSet::new(),
        strict: false,
    };

    let report = validate_project(Some(&wrangler_config), &options).unwrap();

    assert!(!report.is_success, "Expected validation to fail due to undeclared bindings");
    assert_eq!(report.undeclared_accesses.len(), 2);

    let undeclared_names: Vec<&str> = report.undeclared_accesses.iter().map(|a| a.name.as_str()).collect();
    assert!(undeclared_names.contains(&"MISSING_KV"));
    assert!(undeclared_names.contains(&"NON_EXISTENT_DB"));

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_integration_ghost_bindings_warning() {
    let temp_dir = create_temp_test_project("ghost_proj");

    let wrangler_json = r#"
    {
        "name": "ghost-worker",
        "vars": {
            "USED_VAR": "yes",
            "GHOST_VAR_1": "dead",
            "GHOST_VAR_2": "dead"
        },
        "kv_namespaces": [
            { "binding": "GHOST_KV", "id": "kv123" }
        ]
    }
    "#;

    let worker_ts = r#"
    export default {
        async fetch(request, env, ctx) {
            return new Response(env.USED_VAR);
        }
    };
    "#;

    let config_path = temp_dir.join("wrangler.json");
    let src_dir = temp_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let source_path = src_dir.join("worker.ts");

    fs::write(&config_path, wrangler_json).unwrap();
    fs::write(&source_path, worker_ts).unwrap();

    let wrangler_config = parse_wrangler_config(&config_path).unwrap();

    // Default mode: not strict -> is_success is true because 0 undeclared
    let options = ValidatorOptions {
        target_paths: vec![temp_dir.clone()],
        environment: None,
        ignore_unused: HashSet::new(),
        ignore_undeclared: HashSet::new(),
        strict: false,
    };

    let report = validate_project(Some(&wrangler_config), &options).unwrap();
    assert!(report.is_success, "Default mode succeeds despite ghost warnings");
    assert_eq!(report.ghost_bindings.len(), 3);

    let ghost_names: Vec<&str> = report.ghost_bindings.iter().map(|b| b.name.as_str()).collect();
    assert!(ghost_names.contains(&"GHOST_VAR_1"));
    assert!(ghost_names.contains(&"GHOST_VAR_2"));
    assert!(ghost_names.contains(&"GHOST_KV"));

    // Strict mode: fails when ghost warnings exist
    let strict_options = ValidatorOptions {
        target_paths: vec![temp_dir.clone()],
        environment: None,
        ignore_unused: HashSet::new(),
        ignore_undeclared: HashSet::new(),
        strict: true,
    };

    let strict_report = validate_project(Some(&wrangler_config), &strict_options).unwrap();
    assert!(!strict_report.is_success, "Strict mode must fail when ghost bindings exist");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_integration_environment_overrides() {
    let temp_dir = create_temp_test_project("env_override_proj");

    let wrangler_toml = r#"
    name = "env-worker"

    [vars]
    COMMON_VAR = "common"
    DEV_ONLY_VAR = "dev"

    [env.production]
    vars = { COMMON_VAR = "prod", PROD_SECRET = "prod-secret" }
    [[env.production.kv_namespaces]]
    binding = "PROD_KV"
    id = "kv-prod"
    "#;

    let worker_ts = r#"
    export default {
        async fetch(request, env, ctx) {
            console.log(env.COMMON_VAR);
            console.log(env.PROD_SECRET);
            console.log(env.PROD_KV);
            return new Response("ok");
        }
    };
    "#;

    let config_path = temp_dir.join("wrangler.toml");
    let src_dir = temp_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let source_path = src_dir.join("worker.ts");

    fs::write(&config_path, wrangler_toml).unwrap();
    fs::write(&source_path, worker_ts).unwrap();

    let wrangler_config = parse_wrangler_config(&config_path).unwrap();

    // 1. Validate root environment: PROD_SECRET and PROD_KV are missing -> 2 errors
    let root_options = ValidatorOptions {
        target_paths: vec![temp_dir.clone()],
        environment: None,
        ignore_unused: HashSet::new(),
        ignore_undeclared: HashSet::new(),
        strict: false,
    };
    let root_report = validate_project(Some(&wrangler_config), &root_options).unwrap();
    assert_eq!(root_report.undeclared_accesses.len(), 2);

    // 2. Validate production environment: PROD_SECRET, PROD_KV, and inherited COMMON_VAR exist -> 0 errors!
    let prod_options = ValidatorOptions {
        target_paths: vec![temp_dir.clone()],
        environment: Some("production".to_string()),
        ignore_unused: HashSet::new(),
        ignore_undeclared: HashSet::new(),
        strict: false,
    };
    let prod_report = validate_project(Some(&wrangler_config), &prod_options).unwrap();
    assert_eq!(prod_report.undeclared_accesses.len(), 0);
    assert!(prod_report.is_success);

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_integration_ignore_directives() {
    let temp_dir = create_temp_test_project("ignore_proj");

    let wrangler_toml = r#"
    name = "ignore-worker"
    "#;

    let worker_ts = r#"
    export default {
        async fetch(request, env, ctx) {
            // cf-ignore
            const ignoredVal = env.IGNORED_UNDECLARED;

            // Normal undeclared
            const unhandledVal = env.REAL_UNDECLARED;

            return new Response("ok");
        }
    };
    "#;

    let config_path = temp_dir.join("wrangler.toml");
    let src_dir = temp_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let source_path = src_dir.join("worker.ts");

    fs::write(&config_path, wrangler_toml).unwrap();
    fs::write(&source_path, worker_ts).unwrap();

    let wrangler_config = parse_wrangler_config(&config_path).unwrap();
    let options = ValidatorOptions {
        target_paths: vec![temp_dir.clone()],
        environment: None,
        ignore_unused: HashSet::new(),
        ignore_undeclared: HashSet::new(),
        strict: false,
    };

    let report = validate_project(Some(&wrangler_config), &options).unwrap();
    assert_eq!(report.undeclared_accesses.len(), 1);
    assert_eq!(report.undeclared_accesses[0].name, "REAL_UNDECLARED");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_integration_output_reporters() {
    let temp_dir = create_temp_test_project("report_format_proj");

    let wrangler_jsonc = r#"{ "name": "demo", "vars": { "PORT": "3000" } }"#;
    let worker_ts = r#"export default { fetch(req, env) { return new Response(env.PORT); } };"#;

    let config_path = temp_dir.join("wrangler.jsonc");
    let src_dir = temp_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let source_path = src_dir.join("index.ts");

    fs::write(&config_path, wrangler_jsonc).unwrap();
    fs::write(&source_path, worker_ts).unwrap();

    let wrangler_config = parse_wrangler_config(&config_path).unwrap();
    let options = ValidatorOptions {
        target_paths: vec![temp_dir.clone()],
        environment: None,
        ignore_unused: HashSet::new(),
        ignore_undeclared: HashSet::new(),
        strict: false,
    };

    let report = validate_project(Some(&wrangler_config), &options).unwrap();

    // Verify all 3 rendering modes execute without panicking
    assert!(render_report(&report, OutputFormat::Text).is_ok());
    assert!(render_report(&report, OutputFormat::Json).is_ok());
    assert!(render_report(&report, OutputFormat::Sarif).is_ok());

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}
