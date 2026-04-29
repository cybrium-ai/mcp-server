#!/usr/bin/env node
/**
 * Cybrium MCP Server — exposes cyscan, cyweb, and cyprobe as MCP tools
 * for AI coding assistants (Claude Code, Cursor, Windsurf, etc.)
 *
 * Tools:
 *   scan          — SAST/SCA/secrets scan (cyscan)
 *   supply        — dependency vulnerability scan
 *   health        — repository security health check
 *   frameworks    — detect frameworks in codebase
 *   web_scan      — web vulnerability scan (cyweb)
 *   discover      — network device discovery (cyprobe)
 *   fix           — apply autofix for findings
 *
 * Install: npm install -g @cybrium-ai/mcp-server
 * Configure in claude_desktop_config.json:
 *   { "mcpServers": { "cybrium": { "command": "cybrium-mcp" } } }
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execSync, execFileSync } from "child_process";
import * as path from "path";

// ── Tool Helpers ─────────────────────────────────────────────────────────────

function findBinary(name: string): string | null {
  const candidates = [
    `/opt/homebrew/bin/${name}`,
    `/usr/local/bin/${name}`,
    `/usr/bin/${name}`,
    path.join(process.env.HOME || "", `.cargo/bin/${name}`),
  ];
  for (const c of candidates) {
    try {
      execSync(`test -f ${c}`, { stdio: "ignore" });
      return c;
    } catch { /* not found */ }
  }
  try {
    return execSync(`which ${name}`, { timeout: 3000 }).toString().trim();
  } catch {
    return null;
  }
}

function runTool(binary: string, args: string[], timeout = 60000): string {
  try {
    const result = execFileSync(binary, args, {
      timeout,
      maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, CYSCAN_RULES: process.env.CYSCAN_RULES || "" },
    });
    return result.toString();
  } catch (err: any) {
    if (err.stdout) return err.stdout.toString();
    throw new Error(`${binary} failed: ${err.message}`);
  }
}

// ── MCP Server ───────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "cybrium",
  version: "0.1.0",
});

// ── Tool: scan ───────────────────────────────────────────────────────────────

server.tool(
  "scan",
  "Run a SAST/SCA/secrets security scan on source code. Returns vulnerability findings with severity, CWE, file location, and fix suggestions. Supports Python, JavaScript, TypeScript, Go, Java, Ruby, PHP, Rust, C, Terraform, Docker, and 9 more languages. 1,067 built-in rules.",
  {
    target: z.string().describe("File or directory path to scan").default("."),
    format: z.enum(["json", "text", "sarif"]).describe("Output format").default("json"),
  },
  async ({ target, format }) => {
    const bin = findBinary("cyscan");
    if (!bin) return { content: [{ type: "text" as const, text: "cyscan not installed. Run: brew install cybrium-ai/cli/cyscan" }] };

    const output = runTool(bin, ["scan", target, "--format", format]);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// ── Tool: supply ─────────────────────────────────────────────────────────────

server.tool(
  "supply_chain_scan",
  "Scan dependency lockfiles for known vulnerabilities (CVEs), typosquat packages, and license policy violations. Supports package-lock.json, yarn.lock, Pipfile.lock, Cargo.lock, go.sum, Gemfile.lock, composer.lock.",
  {
    target: z.string().describe("Directory containing lockfiles").default("."),
  },
  async ({ target }) => {
    const bin = findBinary("cyscan");
    if (!bin) return { content: [{ type: "text" as const, text: "cyscan not installed." }] };

    const output = runTool(bin, ["supply", target, "--format", "json"]);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// ── Tool: health ─────────────────────────────────────────────────────────────

server.tool(
  "repo_health",
  "Check repository security health — 14 checks covering governance (LICENSE, SECURITY.md, CODEOWNERS), secrets (.env, hardcoded credentials), supply chain (lockfiles, Dependabot), container security (Dockerfile non-root), and code hygiene (security TODOs). Returns a score 0-100.",
  {
    target: z.string().describe("Repository root directory").default("."),
  },
  async ({ target }) => {
    const bin = findBinary("cyscan");
    if (!bin) return { content: [{ type: "text" as const, text: "cyscan not installed." }] };

    const output = runTool(bin, ["health", target, "--format", "json"]);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// ── Tool: frameworks ─────────────────────────────────────────────────────────

server.tool(
  "detect_frameworks",
  "Detect which frameworks and libraries are used in the codebase. Identifies 35 frameworks across Python (Django, Flask, FastAPI), JavaScript (React, Next.js, Express, Vue, Angular), Java (Spring Boot, Hibernate), Go (Gin, Echo), Ruby (Rails), PHP (Laravel, Symfony), Rust (Actix, Axum), and Terraform (AWS/Azure/GCP).",
  {
    target: z.string().describe("Directory to analyze").default("."),
  },
  async ({ target }) => {
    const bin = findBinary("cyscan");
    if (!bin) return { content: [{ type: "text" as const, text: "cyscan not installed." }] };

    const output = runTool(bin, ["frameworks", target, "--format", "json"]);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// ── Tool: fix ────────────────────────────────────────────────────────────────

server.tool(
  "fix",
  "Apply automatic security fixes to source code. Uses cyscan's built-in fix recipes to patch vulnerabilities in-place. Creates .cyscan-bak backup files. Use --dry-run to preview changes without modifying files.",
  {
    target: z.string().describe("File or directory to fix"),
    dry_run: z.boolean().describe("Preview fixes without applying").default(true),
  },
  async ({ target, dry_run }) => {
    const bin = findBinary("cyscan");
    if (!bin) return { content: [{ type: "text" as const, text: "cyscan not installed." }] };

    const args = ["fix", target];
    if (dry_run) args.push("--dry-run");

    const output = runTool(bin, args);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// ── Tool: web_scan ───────────────────────────────────────────────────────────

server.tool(
  "web_scan",
  "Scan a web application or URL for vulnerabilities — checks HTTP headers, server misconfigurations, known CVE paths, directory listings, and security headers (CSP, HSTS, X-Frame-Options). Fast scanner built in Rust.",
  {
    target: z.string().describe("URL to scan (e.g., https://example.com)"),
  },
  async ({ target }) => {
    const bin = findBinary("cyweb");
    if (!bin) return { content: [{ type: "text" as const, text: "cyweb not installed. Run: brew install cybrium-ai/cli/cyweb" }] };

    const output = runTool(bin, ["scan", target, "--format", "json"], 120000);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// ── Tool: discover ───────────────────────────────────────────────────────────

server.tool(
  "network_discover",
  "Discover devices on the local network — ARP scanning, OUI vendor lookup, service fingerprinting. Identifies IoT devices, medical equipment, OT/SCADA systems, printers, and network infrastructure.",
  {
    targets: z.string().describe("Subnet to scan (e.g., 192.168.1.0/24)").default("auto"),
    interface: z.string().describe("Network interface (e.g., en0)").default("auto"),
  },
  async ({ targets, interface: iface }) => {
    const bin = findBinary("cyprobe");
    if (!bin) return { content: [{ type: "text" as const, text: "cyprobe not installed. Run: brew install cybrium-ai/cli/cyprobe" }] };

    const args = ["discover"];
    if (targets !== "auto") { args.push("--targets", targets); }
    if (iface !== "auto") { args.push("--interface", iface); }
    args.push("--format", "json");

    const output = runTool(bin, args, 120000);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// ── Start ────────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
