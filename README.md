# 🛡️ Flareguard

> **The Unified Cloudflare Security & Architecture Guardian**  
> High-performance Rust CLI & library providing AST secret scanning, Worker binding verification, Zone security posture auditing, and origin IP leak hunting.

[![CI](https://github.com/bhubbard/flareguard/actions/workflows/ci.yml/badge.svg)](https://github.com/bhubbard/flareguard/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub Pages](https://img.shields.io/badge/docs-bhubbard.github.io-blue)](https://bhubbard.github.io/flareguard)

---

## ⚡ The 4 Pillars of Flareguard

| Pillar | Subcommand | Description |
|---|---|---|
| **🔑 Secrets** | `flareguard secrets` | High-throughput multithreaded scanner preventing Cloudflare API tokens, Global Keys, and Turnstile secrets from leaking into client bundles or git history. |
| **⚡ Bindings** | `flareguard bindings` | OXC JavaScript/TypeScript AST scanner that cross-references `wrangler.toml` / `wrangler.jsonc` declarations against actual code usage (D1, KV, R2, Vectorize, Hyperdrive, AI). |
| **🌐 Zone Audit** | `flareguard zone` | Comprehensive live security posture auditor for Cloudflare zones (SSL/TLS Strict, HSTS, WAF Managed Rules, Bot Fight Mode, DNSSEC, security headers). |
| **🎯 Origin Hunter** | `flareguard origin` | Probes and discovers unmasked backend origin IPs behind Cloudflare reverse proxies using DNS SPF/MX records, CRT.sh Certificate Transparency logs, and active HTTP signatures. |

---

## 🚀 Installation & Quickstart

```bash
# Install via Cargo
cargo install flareguard

# Or build from source
git clone https://github.com/bhubbard/flareguard.git
cd flareguard
cargo build --release
```

### 1. Scan for Leaked Cloudflare Secrets
```bash
# Scan static build directory (e.g. dist, public)
flareguard secrets dist/

# Run in CI mode (fails with exit code 1 on leaks)
flareguard secrets dist/ --check --format sarif --output results.sarif
```

### 2. Validate Worker / Pages Bindings
```bash
# Validate wrangler.jsonc or wrangler.toml against src/ AST usage
flareguard bindings src/ --config wrangler.jsonc --strict
```

### 3. Audit Cloudflare Zone Security
```bash
# Live zone audit via API Token
flareguard zone --token $CF_API_TOKEN --zone example.com --check

# Offline mock audit
flareguard zone --mock
```

### 4. Hunt for Unmasked Origin IPs
```bash
# Scan domain for direct-to-origin leak vectors
flareguard origin example.com --check

# Offline mock scan
flareguard origin --mock
```

### 5. End-to-End Workspace Check
```bash
# Run all local security checks across repository
flareguard check .
```

---

## 📜 Architecture & Core Principles

- **Zero-Latency Parallelism:** Rayon-powered parallel directory traversal and memory-mapped file inspection (`memmap2`).
- **Precision AST Analysis:** Powered by **OXC** (Oxford JavaScript Compiler in Rust) for nanosecond JS/TS parsing without runtime node/v8 dependencies.
- **Actionable Remediation:** Every finding includes clear, copy-paste shell commands and Cloudflare dashboard remediation instructions.
- **Enterprise CI/CD Integration:** Direct SARIF output for GitHub Actions Code Scanning and customizable compliance gates.

---

## 📄 License
MIT © 2026 Brandon Hubbard ([brandonhubbard.com](https://brandonhubbard.com))
