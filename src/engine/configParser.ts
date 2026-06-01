// Real MCP config file parser.
// Understands the actual formats used by Claude Desktop, Cursor, VS Code,
// raw tools/list JSON-RPC responses, and plain MCP server definitions.

import type { MCPServer, MCPTool } from "./types";

export interface ParseResult {
  servers: MCPServer[];
  format: string;
  warnings: string[];
}

// Master parser — detects format and extracts MCP servers/tools.
export function parseConfig(raw: string): ParseResult {
  const trimmed = raw.trim();
  const warnings: string[] = [];

  let obj: unknown;
  try {
    obj = JSON.parse(trimmed);
  } catch (e) {
    throw new Error(`Invalid JSON: ${(e as Error).message}`);
  }

  if (!obj || typeof obj !== "object") {
    throw new Error("Expected a JSON object or array.");
  }

  // 1. Claude Desktop config: { mcpServers: { "name": { command, args, env } } }
  const asRecord = obj as Record<string, unknown>;
  if (asRecord.mcpServers && typeof asRecord.mcpServers === "object") {
    return parseClaudeDesktopConfig(asRecord.mcpServers as Record<string, unknown>, warnings);
  }

  // 2. Cursor/VS Code config: { "mcp.servers": { ... } } or { servers: { ... } }
  if (asRecord["mcp.servers"] && typeof asRecord["mcp.servers"] === "object") {
    return parseCursorConfig(asRecord["mcp.servers"] as Record<string, unknown>, warnings);
  }

  // 3. JSON-RPC tools/list response: { result: { tools: [...] } } or { tools: [...] }
  if (asRecord.result && typeof asRecord.result === "object") {
    const result = asRecord.result as Record<string, unknown>;
    if (Array.isArray(result.tools)) {
      return parseToolsList(result.tools, warnings);
    }
  }

  // 4. Direct tools array: { tools: [...] } — our original format
  if (Array.isArray(asRecord.tools)) {
    return parseDirect(asRecord as Record<string, unknown>, warnings);
  }

  // 5. Bare array of tools: [{ name, description, inputSchema }]
  if (Array.isArray(obj)) {
    const tools = (obj as unknown[]).filter(isToolLike).map(normalizeTool);
    if (tools.length > 0) {
      return {
        servers: [{ name: "unnamed-server", tools }],
        format: "Bare tools array",
        warnings,
      };
    }
  }

  // 6. Object with server-name keys: { "server-a": { command, tools? }, ... }
  const keys = Object.keys(asRecord);
  if (keys.length > 0 && keys.every((k) => typeof asRecord[k] === "object" && asRecord[k] !== null)) {
    const attempt = parseServerMap(asRecord, warnings);
    if (attempt.servers.length > 0) return attempt;
  }

  throw new Error(
    'Could not detect format. Supported: Claude Desktop config, Cursor config, JSON-RPC tools/list response, direct {tools:[...]} definition, or a bare tools array.'
  );
}

// --- Claude Desktop: ~/.config/claude/claude_desktop_config.json ---
function parseClaudeDesktopConfig(mcpServers: Record<string, unknown>, warnings: string[]): ParseResult {
  const servers: MCPServer[] = [];
  for (const [name, cfg] of Object.entries(mcpServers)) {
    if (!cfg || typeof cfg !== "object") continue;
    const c = cfg as Record<string, unknown>;
    const server: MCPServer = {
      name,
      transport: typeof c.command === "string" ? "stdio" : (typeof c.url === "string" ? "http" : "stdio"),
      url: typeof c.url === "string" ? c.url : undefined,
      tools: [],
    };

    // Extract info about the server for security analysis
    const meta: Record<string, unknown> = {};
    if (c.command) meta.command = c.command;
    if (c.args) meta.args = c.args;
    if (c.env) {
      meta.env = c.env;
      // Check env for leaked secrets
      const envObj = c.env as Record<string, string>;
      for (const [ek, ev] of Object.entries(envObj)) {
        if (typeof ev === "string" && ev.length > 0) {
          // Create a synthetic tool to scan the env vars
          server.tools.push({
            name: `__env__${ek}`,
            description: `Environment variable ${ek} = ${maskSecret(ev)}`,
            inputSchema: { type: "object", properties: { [ek]: { type: "string", description: ev } } },
          });
        }
      }
    }

    // Create a synthetic tool describing the server's command surface
    if (c.command) {
      const cmdParts = [c.command, ...(Array.isArray(c.args) ? c.args : [])].join(" ");
      server.tools.push({
        name: `__server_command__`,
        description: `Server launch command: ${cmdParts}`,
        inputSchema: { type: "object", properties: {} },
      });
    }

    if (server.tools.length === 0) {
      warnings.push(
        `Server "${name}": Claude Desktop config defines the server process but not its tools. ` +
        `To scan actual tool definitions, run the server and paste the tools/list response.`
      );
      // Still add it with a placeholder
      server.tools.push({
        name: "__no_tools_defined__",
        description: `No tool definitions available in config. Server: ${name}`,
      });
    }

    servers.push(server);
  }
  return { servers, format: "Claude Desktop config (claude_desktop_config.json)", warnings };
}

// --- Cursor: settings.json with "mcp.servers" ---
function parseCursorConfig(mcp: Record<string, unknown>, warnings: string[]): ParseResult {
  // Cursor format is similar to Claude Desktop
  return parseClaudeDesktopConfig(mcp, warnings);
}

// --- JSON-RPC tools/list response ---
function parseToolsList(tools: unknown[], warnings: string[]): ParseResult {
  const parsed = tools.filter(isToolLike).map(normalizeTool);
  if (parsed.length === 0) {
    warnings.push("tools/list response contained no valid tool definitions.");
  }
  return {
    servers: [{ name: "server (from tools/list)", tools: parsed }],
    format: "JSON-RPC tools/list response",
    warnings,
  };
}

// --- Direct {name, tools: [...]} ---
function parseDirect(obj: Record<string, unknown>, warnings: string[]): ParseResult {
  const tools = (obj.tools as unknown[]).filter(isToolLike).map(normalizeTool);
  return {
    servers: [{
      name: (typeof obj.name === "string" ? obj.name : "unnamed-server"),
      version: typeof obj.version === "string" ? obj.version : undefined,
      transport: typeof obj.transport === "string" ? obj.transport : undefined,
      tools,
    }],
    format: "Direct MCP server definition",
    warnings,
  };
}

// --- Multi-server map ---
function parseServerMap(obj: Record<string, unknown>, warnings: string[]): ParseResult {
  const servers: MCPServer[] = [];
  for (const [name, val] of Object.entries(obj)) {
    if (!val || typeof val !== "object") continue;
    const v = val as Record<string, unknown>;
    // If it looks like a Claude Desktop entry
    if (v.command || v.url || v.args) {
      const sub = parseClaudeDesktopConfig({ [name]: v }, []);
      servers.push(...sub.servers);
      warnings.push(...sub.warnings);
    } else if (Array.isArray(v.tools)) {
      const tools = (v.tools as unknown[]).filter(isToolLike).map(normalizeTool);
      servers.push({ name, tools });
    }
  }
  return { servers, format: "Multi-server configuration", warnings };
}

function isToolLike(t: unknown): boolean {
  if (!t || typeof t !== "object") return false;
  const obj = t as Record<string, unknown>;
  return typeof obj.name === "string" || typeof obj.description === "string";
}

function normalizeTool(t: unknown): MCPTool {
  const obj = t as Record<string, unknown>;
  return {
    name: typeof obj.name === "string" ? obj.name : "(unnamed)",
    description: typeof obj.description === "string" ? obj.description : "",
    inputSchema: obj.inputSchema as MCPTool["inputSchema"],
    annotations: obj.annotations as MCPTool["annotations"],
  };
}

function maskSecret(val: string): string {
  if (val.length <= 8) return "***";
  return val.slice(0, 4) + "..." + val.slice(-4);
}

// --- Live MCP endpoint probe ---
export async function probeMCPEndpoint(url: string): Promise<ParseResult> {
  const warnings: string[] = [];

  // Normalize URL
  let endpoint = url.trim();
  if (!endpoint.startsWith("http")) endpoint = "http://" + endpoint;

  // Try JSON-RPC tools/list call
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
    params: {},
  });

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }

    const data = await res.json();

    if (data.error) {
      throw new Error(`JSON-RPC error: ${data.error.message || JSON.stringify(data.error)}`);
    }

    if (data.result && Array.isArray(data.result.tools)) {
      return parseToolsList(data.result.tools, warnings);
    }

    // Maybe it's a REST-style response
    if (Array.isArray(data.tools)) {
      return parseDirect(data, warnings);
    }
    if (Array.isArray(data)) {
      const tools = data.filter(isToolLike).map(normalizeTool);
      return { servers: [{ name: endpoint, tools }], format: "REST endpoint", warnings };
    }

    throw new Error("Response did not contain a tools array.");
  } catch (e) {
    const msg = (e as Error).message;
    if (msg.includes("Failed to fetch") || msg.includes("NetworkError") || msg.includes("CORS")) {
      throw new Error(
        `Could not reach ${endpoint}. This is usually a CORS issue — browsers block cross-origin requests to local servers. ` +
        `Instead, run this in your terminal:\n\n` +
        `curl -X POST ${endpoint} -H "Content-Type: application/json" -d '${body}'\n\n` +
        `Then paste the response here.`
      );
    }
    throw new Error(`Probe failed: ${msg}`);
  }
}
