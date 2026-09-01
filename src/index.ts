#!/usr/bin/env node
/**
 * Cybrium MCP Server — exposes cyscan, cyweb, cyprobe and cynet as MCP tools
 * for AI coding assistants (Claude Code, Cursor, Windsurf, etc.)
 *
 * Tools:
 *   scan          — SAST/SCA/secrets scan (cyscan)
 *   supply        — dependency vulnerability scan
 *   health        — repository security health check
 *   frameworks    — detect frameworks in codebase
 *   web_scan      — web vulnerability scan (cyweb)
 *   network_discover — network device discovery (cyprobe)
 *   network_scan  — host / port / service / OS scan (cynet)
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
    // A tool that exits non-zero often still produced usable JSON on stdout
    // (partial scan, findings-present exit codes), so prefer that.
    const out = err.stdout ? err.stdout.toString().trim() : "";
    if (out) return out;
    // Otherwise surface stderr. Returning "" here made a failed invocation
    // look like a clean empty result to the model — the worst outcome for a
    // security tool, because "no output" reads as "nothing found".
    const errText = err.stderr ? err.stderr.toString().trim() : "";
    throw new Error(`${binary} failed: ${errText || err.message}`);
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

// ── Tool: network_scan (cynet) ───────────────────────────────────────────────

server.tool(
  "network_scan",
  "Scan a host or network for open ports, services, and OS — host discovery plus port/service detection, OS fingerprinting, and exposed-service / protocol-hygiene findings (cleartext services, unauthenticated datastores, exposed admin planes). Fast native scanner. Accepts a host, IP, or CIDR.",
  {
    target: z.string().describe("Host, IP, or CIDR to scan (e.g., 192.168.1.10 or 10.0.0.0/24)"),
  },
  async ({ target }) => {
    const bin = findBinary("cynet");
    if (!bin) return { content: [{ type: "text" as const, text: "cynet not installed. Run: brew install cybrium-ai/cli/cynet" }] };

    const output = runTool(bin, ["scan", target, "--format", "json"], 300000);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// ── Tool: ai_discover (cyradar discover) ────────────────────────────────────
//
// v0.3.0 — the marquee AI-security search hit. When a developer asks
// Claude/Cursor/Windsurf "find AI inference servers on our network" or
// "are there unauthorised Ollama instances on the LAN," THIS is the
// tool the agent picks. Tight tool name (`ai_discover`) + AI-forward
// description optimises for both vector-search and keyword-match
// scoring inside MCP host clients.

server.tool(
  "ai_discover",
  "Discover self-hosted AI inference servers (Ollama, vLLM, TGI, LocalAI, Triton, LM Studio, llama.cpp, OpenAI-compatible) on a network. Sweeps CIDR ranges or host lists, fingerprints each endpoint by signature catalogue, returns product + version + endpoint + confidence + evidence. Use when the user asks about AI inventory, shadow AI, AI governance, or finding unauthorised LLM deployments.",
  {
    targets: z.string().describe("Targets — one or more of: bare host, host:port, http(s)://url, or CIDR (e.g. 10.0.0.0/24). Comma-separated."),
  },
  async ({ targets }) => {
    const bin = findBinary("cyradar");
    if (!bin) return { content: [{ type: "text" as const, text: "cyradar not installed. Run: brew install cybrium-ai/cli/cyradar" }] };

    const output = runTool(bin, ["discover", "--targets", targets, "--format", "json"], 300000);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// ── Tool: ai_local_scan (cyradar local-scan) ────────────────────────────────

server.tool(
  "ai_local_scan",
  "Inventory AI tooling installed on the local machine: AI CLIs (ollama, openai, claude, anthropic, etc.), IDE AI extensions (Copilot, Continue, Cline, Cursor settings), desktop AI apps (LM Studio, Ollama.app, Anything LLM), and on-disk model files (GGUF, safetensors, ONNX). Use when the user asks 'what AI tools do I have installed', for shadow-AI audits, or for AI BOM / AIBOM generation.",
  {},
  async () => {
    const bin = findBinary("cyradar");
    if (!bin) return { content: [{ type: "text" as const, text: "cyradar not installed. Run: brew install cybrium-ai/cli/cyradar" }] };

    const output = runTool(bin, ["local-scan", "--format", "json"], 60000);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// ── Tool: email_security_scan (cymail) ──────────────────────────────────────

server.tool(
  "email_security_scan",
  "Score a domain's email security posture — checks SPF, DKIM, DMARC, MTA-STS, BIMI, DNSSEC, TLS-RPT, and ARC. Use when the user asks about email spoofing protection, phishing risk for a domain, or running an email-security audit.",
  {
    domain: z.string().describe("Domain to audit (e.g., example.com — not a full URL)"),
  },
  async ({ domain }) => {
    const bin = findBinary("cymail");
    if (!bin) return { content: [{ type: "text" as const, text: "cymail not installed. Run: brew install cybrium-ai/cli/cymail" }] };

    // cymail takes the domain as a --domain flag, not positionally.
    const output = runTool(bin, ["scan", "--domain", domain, "--format", "json"], 60000);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// ── Start ────────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
