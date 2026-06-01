# MCPShield Toolkit

A real MCP security toolkit: a browser-based static analyzer **and** a Node.js runtime proxy that intercepts live MCP traffic.

## What's in this repo

```
src/
├── engine/                  # Shared analysis engine (browser + Node)
│   ├── types.ts            # Domain types
│   ├── parser.ts           # Auto-detect 6 input formats
│   ├── analyzer.ts         # 30+ static analysis rules
│   ├── llm.ts              # Groq LLM integration (optional)
│   └── export.ts           # JSON + PDF export
├── proxy/                   # Node.js runtime proxy daemon
│   ├── server.ts           # Express proxy + analyzer + dashboard
│   ├── analyzer.ts         # Re-exports for Node
│   └── cli.ts              # `mcpshield-proxy` CLI (init/start/check/mcp-bridge)
├── components/             # React UI primitives
├── App.tsx                 # Browser app entry
├── main.tsx
└── index.css
tests/
└── proxy.test.mjs          # Self-test: spawn fake upstream, verify detection
```

## Two ways to use it

### 1. Browser app (static analysis only)
Visit the deployed site, paste your `claude_desktop_config.json`, get a security report.

Limitations: the browser app reads only the config you give it. It cannot inspect what an MCP server does at runtime.

### 2. Runtime proxy (catches what the browser can't)

```bash
# Install (or run from source):
npx tsx src/proxy/cli.ts init -o ./mcpshield.json
# Edit mcpshield.json to list your upstream MCP servers
npx tsx src/proxy/cli.ts start --config ./mcpshield.json --mode monitor
```

Then point your MCP client at the proxy:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["tsx", "<repo>/src/proxy/cli.ts", "mcp-bridge", "filesystem", "--proxy", "http://localhost:7777"]
    }
  }
}
```

The proxy:
- Forwards every JSON-RPC call to the real upstream
- Inspects every `tools/list` response (the **actual** tool definitions the server returned, not just the config)
- Optionally calls the LLM (Groq free tier) for semantic review
- In `enforce` mode, blocks `tools/call` requests that target flagged tools
- Serves a live dashboard at `http://localhost:7777/dashboard`
- Persists every call to `mcpshield-state.json`

## Free LLM setup (optional)

```bash
# Get a free key at https://console.groq.com/keys
export GROQ_API_KEY=gsk_xxxxxxxx
export GROQ_MODEL=llama-3.1-8b-instant   # default
```

## Run the self-test

```bash
npx tsx tests/proxy.test.mjs
```

This spawns a fake MCP server with one clean and one poisoned tool, runs the proxy, and verifies the poisoned tool is caught.

## Honest limitations

See the "Honest assessment" section in the browser app, or read the inline `Feedback()` component in `src/App.tsx`.
