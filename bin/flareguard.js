#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const exe = process.platform === "win32" ? "flareguard.exe" : "flareguard";

const PLATFORM_PACKAGES = {
  "darwin-arm64": "@flareguard/darwin-arm64",
  "darwin-x64": "@flareguard/darwin-x64",
  "linux-x64": "@flareguard/linux-x64",
  "linux-arm64": "@flareguard/linux-arm64",
  "win32-x64": "@flareguard/win32-x64",
};

export function getBinaryPath() {
  if (process.env.FLAREGUARD_BIN && fs.existsSync(process.env.FLAREGUARD_BIN)) {
    return process.env.FLAREGUARD_BIN;
  }

  // 1. Check if optional platform-specific package is installed
  const platformKey = `${process.platform}-${process.arch}`;
  const pkgName = PLATFORM_PACKAGES[platformKey];
  if (pkgName) {
    try {
      const resolved = require.resolve(`${pkgName}/bin/${exe}`);
      if (fs.existsSync(resolved)) {
        return resolved;
      }
    } catch {
      // Platform package not present; fall through
    }
  }

  // 2. Check local builds or vendored binary locations
  const candidates = [
    path.resolve(root, "dist/bin", exe),
    path.resolve(root, "target/release", exe),
    path.resolve(root, "target/debug", exe),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      if (process.platform !== "win32") {
        try {
          const mode = fs.statSync(candidate).mode;
          if ((mode & 0o111) === 0) {
            fs.chmodSync(candidate, 0o755);
          }
        } catch {
          // Ignore
        }
      }
      return candidate;
    }
  }

  return exe;
}

const bin = getBinaryPath();
const res = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
if (res.error) {
  if (res.error.code === "ENOENT") {
    console.error(`[flareguard] Could not find native binary '${bin}'.`);
    console.error("Please run `cargo build --release` or install flareguard via Cargo or prebuilt npm platform package.");
  } else {
    console.error(`[flareguard] Execution error: ${res.error.message}`);
  }
  process.exit(1);
}
process.exit(res.status ?? 0);
