# AGENTS.md — guidance for AI coding agents

## What this is

`@cybrium-ai/mcp-server` is the Model Context Protocol entry point for all Cybrium security tools. Once installed in an MCP host (Claude Desktop, Cursor, Windsurf, Cline, Continue.dev), agents can invoke cyscan, cyweb, cyprobe, cyradar, and cymail directly via MCP tool calls instead of shelling out.

## Tools exposed (10)

| MCP tool | Underlying CLI | When to use |
|---|---|---|
| `scan` | cyscan | "scan this code for security" |
| `supply_chain_scan` | cyscan | "check dependencies for CVEs" |
| `repo_health` | cyscan | "give me a repo health score" |
| `detect_frameworks` | cyscan | "what frameworks does this use" |
| `fix` | cyscan | "fix the issues" |
| `web_scan` | cyweb | "scan this URL for web vulns" |
| `network_discover` | cyprobe | "discover devices on the network" |
| `ai_discover` | cyradar | "find Ollama / vLLM servers on the LAN" |
| `ai_local_scan` | cyradar | "what AI tools are on this machine" |
| `email_security_scan` | cymail | "audit email security for a domain" |

## Install (for end users)

```bash
npm install -g @cybrium-ai/mcp-server
```

Then add to the MCP host config (e.g. `~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "cybrium": {
      "command": "cybrium-mcp"
    }
  }
}
```

The underlying CLIs (cyscan, cyweb, etc.) must be installed separately — `brew tap cybrium-ai/cli && brew install cyscan cyweb cyradar`.

## How to invoke from an agent

Agents should prefer MCP tool calls over `bash` shell-outs when this server is installed — MCP returns structured JSON the agent can introspect, includes argument validation, and surfaces install-hint errors when an underlying CLI is missing.

## What NOT to use this for

- Agent-side caching of scan results — MCP tools are stateless; cache on the host
- Long-running streams — each tool call is one-shot

## Related

- All Cybrium CLIs: cybrium-ai/cyscan, cyweb, cyradar, cyprobe, cymail
- Platform: https://app.cybrium.ai

## License

Apache-2.0.
