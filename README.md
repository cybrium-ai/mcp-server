# Cybrium MCP Server

MCP (Model Context Protocol) server that gives AI coding assistants real-time security scanning superpowers.

Works with **Claude Code**, **Claude Desktop**, **Cursor**, **Windsurf**, and any MCP-compatible AI tool.

## What You Get

| Tool | Binary | What it does |
|------|--------|-------------|
| `scan` | cyscan | SAST + secrets + IaC scan — 1,815 rules, 75+ languages, 296 secret patterns |
| `supply_chain_scan` | cyscan | Dependency CVE + typosquat + license compliance |
| `repo_health` | cyscan | 14 security hygiene checks (score 0-100) |
| `detect_frameworks` | cyscan | Identify 35 frameworks across 9 languages |
| `fix` | cyscan | Apply automatic security fixes (with dry-run) |
| `web_scan` | cyweb | Web vulnerability scanner (headers, CVE paths, configs) |
| `network_discover` | cyprobe | Network device discovery (ARP, OUI, services) |

## Prerequisites

Install the Cybrium CLI tools:

```bash
brew tap cybrium-ai/cli
brew install cyscan cyweb cyprobe
```

Verify installation:

```bash
cyscan --version    # should show 0.8.1+
cyweb --version     # should show 0.3.0+
```

---

## Setup: Claude Code (CLI)

### Option 1: One-line command (recommended)

```bash
claude mcp add cybrium -- npx -y @cybrium-ai/mcp-server
```

### Option 2: Manual settings.json

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "cybrium": {
      "command": "npx",
      "args": ["-y", "@cybrium-ai/mcp-server"]
    }
  }
}
```

### Option 3: Global install

```bash
npm install -g @cybrium-ai/mcp-server
```

Then add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "cybrium": {
      "command": "cybrium-mcp"
    }
  }
}
```

### Verify

Restart Claude Code and run:

```
/mcp
```

You should see `cybrium` listed with 7 tools.

---

## Setup: Claude Desktop (macOS)

1. Open Claude Desktop
2. Go to **Settings** (gear icon) > **Developer** > **Edit Config**
3. Add the following to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cybrium": {
      "command": "npx",
      "args": ["-y", "@cybrium-ai/mcp-server"]
    }
  }
}
```

4. Restart Claude Desktop
5. You should see the hammer icon in the chat input — click it to see Cybrium tools

The config file is located at:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

---

## Setup: Cursor

1. Open **Cursor Settings** (Cmd+,)
2. Search for "MCP" in settings
3. Click **Add MCP Server**
4. Enter:
   - **Name:** `cybrium`
   - **Command:** `npx`
   - **Args:** `-y @cybrium-ai/mcp-server`
5. Restart Cursor

---

## Setup: Windsurf

Add to your Windsurf MCP configuration:

```json
{
  "mcpServers": {
    "cybrium": {
      "command": "npx",
      "args": ["-y", "@cybrium-ai/mcp-server"]
    }
  }
}
```

---

## Usage Examples

Once configured, just ask your AI assistant naturally:

### Security Scanning
- "Scan this project for security vulnerabilities"
- "Are there any hardcoded secrets in this codebase?"
- "Check this file for SQL injection issues"

### Supply Chain
- "Check for vulnerable dependencies"
- "Are any of our npm packages typosquatted?"
- "Do we have any AGPL-licensed dependencies?"

### Repository Health
- "How healthy is this repo's security posture?"
- "What's our security score?"

### Frameworks
- "What frameworks does this codebase use?"
- "Detect all the technologies in this project"

### Web Scanning
- "Scan https://staging.example.com for vulnerabilities"
- "Check our API endpoint for security headers"

### Autofix
- "Fix the security issues you found"
- "Apply security fixes in dry-run mode first"

### Network Discovery
- "Discover devices on my local network"
- "What services are running on the network?"

---

## Troubleshooting

### "cybrium-mcp: command not found"

Install globally: `npm install -g @cybrium-ai/mcp-server`

### "cyscan: command not found"

Install via Homebrew:
```bash
brew tap cybrium-ai/cli && brew install cyscan
```

### Tools not showing up

1. Check `/mcp` in Claude Code shows `cybrium`
2. Verify `npx @cybrium-ai/mcp-server` runs without errors
3. Restart your AI tool after adding the config

### Permission issues on macOS

```bash
chmod +x $(which cyscan)
chmod +x $(which cyweb)
```

---

## How It Works

```
Your AI Assistant (Claude/Cursor/Windsurf)
    |
    | MCP Protocol (stdio)
    v
Cybrium MCP Server (Node.js)
    |
    |--- cyscan scan .            → SAST + secrets + IaC findings
    |--- cyscan supply .          → dependency CVEs + licenses
    |--- cyscan health .          → repo health score
    |--- cyscan frameworks .      → framework detection
    |--- cyscan fix .             → autofix patches
    |--- cyweb scan <url>         → web vulnerability scan
    |--- cyprobe discover         → network device discovery
    v
JSON results returned to AI for analysis + remediation
```

The MCP server spawns CLI processes and parses their JSON output. No API keys, no cloud calls, no data leaves your machine.

## License

Apache 2.0
