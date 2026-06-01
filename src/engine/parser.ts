// Real MCP config parser. Auto-detects format, normalizes to NormalizedServer[].
// Supports: Claude Desktop, Cursor, JSON-RPC tools/list, direct, multi-server.

import type { NormalizedServer, NormalizedTool, ParseError } from "./types";

export type ParseResult =
  | { ok: true; servers: NormalizedServer[]; warnings: string[]; format: string }
  | { ok: false; error: ParseError };

export function parseConfig(input: string): ParseResult {
  const trimmed = input.trim();
  if (!trimmed) {
    return { ok: false, error: { type: "format", message: "Empty input. Paste an MCP config or tools/list response." } };
  }

  // JSONC support: strip line and block comments before parsing.
  const stripped = stripJsonComments(trimmed);

  let parsed: unknown;
  try {
    parsed = JSON.parse(stripped);
  } catch (e) {
    const msg = (e as Error).message;
    return {
      ok: false,
      error: {
        type: "json",
        message: `Invalid JSON: ${msg}`,
        details: msg,
      },
    };
  }

  return parseUnknown(parsed, stripped);
}

function parseUnknown(parsed: unknown, rawInput: string): ParseResult {
  if (Array.isArray(parsed)) {
    // bare array of tools or servers
    if (parsed.length === 0) {
      return { ok: false, error: { type: "format", message: "Empty JSON array." } };
    }
    if (looksLikeToolArray(parsed)) {
      const tools = (parsed as unknown[]).map(normalizeTool).filter(isValidTool);
      return {
        ok: true,
        format: "Bare tools array",
        warnings: tools.length === 0 ? ["Array contained no valid tool objects."] : [],
        servers: [{
          name: "array-server",
          transport: "unknown",
          tools,
          sourceFormat: "bare-array",
          warnings: [],
          rawInput: parsed,
        }],
      };
    }
    void rawInput;
    // array of servers?
    if (parsed.every((x) => x && typeof x === "object" && Array.isArray((x as any).tools))) {
      const servers = (parsed as unknown[])
        .map((s, i) => normalizeServer(s, `array[${i}]`, "bare-server-array"))
        .filter((s) => s.tools.length > 0 || s.command || s.url);
      return {
        ok: true,
        format: "Server array",
        warnings: servers.length === 0 ? ["No valid servers found in array."] : [],
        servers,
      };
    }
    return { ok: false, error: { type: "format", message: "Array does not appear to be a tools or servers array." } };
  }

  if (!parsed || typeof parsed !== "object") {
    return { ok: false, error: { type: "format", message: "Expected a JSON object or array." } };
  }

  const obj = parsed as Record<string, unknown>;

  // 1. Claude Desktop: { mcpServers: { name: { command, args, env } } }
  if (obj.mcpServers && typeof obj.mcpServers === "object") {
    return parseServerMap(obj.mcpServers as Record<string, unknown>, "Claude Desktop (claude_desktop_config.json)");
  }

  // 2. Cursor / VS Code: { "mcp.servers": { ... } }
  if (obj["mcp.servers"] && typeof obj["mcp.servers"] === "object") {
    return parseServerMap(obj["mcp.servers"] as Record<string, unknown>, "Cursor/VS Code settings");
  }

  // 3. JSON-RPC tools/list response: { jsonrpc, result: { tools: [...] } }
  if (obj.result && typeof obj.result === "object") {
    const result = obj.result as Record<string, unknown>;
    if (Array.isArray(result.tools)) {
      const tools = (result.tools as unknown[]).map(normalizeTool).filter(isValidTool);
      const meta = (obj.result as any).serverInfo ?? {};
      return {
        ok: true,
        format: "JSON-RPC tools/list response",
        warnings: tools.length === 0 ? ["tools/list returned no tools."] : [],
        servers: [{
          name: typeof meta.name === "string" ? meta.name : "server",
          version: typeof meta.version === "string" ? meta.version : undefined,
          transport: "unknown",
          tools,
          sourceFormat: "jsonrpc-tools-list",
          warnings: [],
          rawInput: parsed,
        }],
      };
    }
  }

  // 4. Direct server definition: { name, tools: [...] }
  if (Array.isArray(obj.tools)) {
    const server = normalizeServer(obj, "(root)", "direct-definition");
    return { ok: true, format: "Direct server definition", warnings: [], servers: [server] };
  }

  // 5. Multi-server map at root: { "name": { command/args/tools } }
  // Heuristic: at least 2 keys, all values are objects.
  const keys = Object.keys(obj);
  if (keys.length >= 1 && keys.every((k) => obj[k] && typeof obj[k] === "object" && !Array.isArray(obj[k]))) {
    const attempt = parseServerMap(obj, "Multi-server map");
    if (attempt.ok && attempt.servers.length > 0) return attempt;
  }

  return {
    ok: false,
    error: {
      type: "format",
      message: "Could not detect format. Supported: Claude Desktop config, Cursor settings, JSON-RPC tools/list response, direct {tools:[]} server definition, bare tool array, or multi-server map.",
    },
  };
}

function parseServerMap(map: Record<string, unknown>, format: string): ParseResult {
  const servers: NormalizedServer[] = [];
  const warnings: string[] = [];
  for (const [name, val] of Object.entries(map)) {
    if (!val || typeof val !== "object") continue;
    const server = normalizeServer(val, name, format);
    if (server.tools.length === 0 && !server.command && !server.url) {
      warnings.push(`Server "${name}": config entry found but no tools, command, or URL defined.`);
    }
    servers.push(server);
  }
  if (servers.length === 0) {
    return { ok: false, error: { type: "format", message: "Server map is empty." } };
  }
  return { ok: true, format, warnings, servers };
}

function normalizeServer(raw: unknown, fallbackName: string, sourceFormat: string): NormalizedServer {
  const obj = (raw ?? {}) as Record<string, unknown>;
  const name = typeof obj.name === "string" ? obj.name : fallbackName;
  const version = typeof obj.version === "string" ? obj.version : undefined;

  // Transport inference
  let transport: NormalizedServer["transport"] = "unknown";
  if (typeof obj.command === "string") transport = "stdio";
  else if (typeof obj.url === "string") {
    const u = obj.url.toLowerCase();
    if (u.startsWith("https://")) transport = "https";
    else if (u.startsWith("http://")) transport = "http";
    else if (u.startsWith("ws://") || u.startsWith("wss://")) transport = "websocket";
    else transport = "unknown";
  } else if (typeof obj.type === "string") {
    const t = obj.type.toLowerCase();
    if (t === "sse" || t === "http" || t === "https" || t === "stdio" || t === "websocket") {
      transport = t as NormalizedServer["transport"];
    }
  }

  const command = typeof obj.command === "string" ? obj.command : undefined;
  const args = Array.isArray(obj.args) ? (obj.args as unknown[]).filter((a) => typeof a === "string") as string[] : undefined;
  const url = typeof obj.url === "string" ? obj.url : undefined;

  let env: Record<string, string> | undefined;
  if (obj.env && typeof obj.env === "object") {
    env = {};
    for (const [k, v] of Object.entries(obj.env as Record<string, unknown>)) {
      if (typeof v === "string") env[k] = v;
      else if (v != null) env[k] = String(v);
    }
  }

  const tools = Array.isArray(obj.tools)
    ? (obj.tools as unknown[]).map(normalizeTool).filter(isValidTool)
    : [];

  const warnings: string[] = [];
  if (command && transport === "stdio") {
    // common security smell: npx -y auto-executes without prompt
    if (args?.includes("-y") && (command === "npx" || command.endsWith("/npx"))) {
      warnings.push(`"${name}": uses 'npx -y' which auto-executes packages without confirmation.`);
    }
    // pulling from npm registry
    if (command === "npx" || command.endsWith("/npx")) {
      const pkg = args?.find((a) => !a.startsWith("-") && a !== "npx" && a.length > 0);
      if (pkg) warnings.push(`"${name}": runs npm package "${pkg}" — verify its publisher and integrity.`);
    }
  }

  return {
    name,
    version,
    transport,
    command,
    args,
    url,
    env,
    tools,
    sourceFormat,
    warnings,
    rawInput: raw,
  };
}

function looksLikeToolArray(arr: unknown[]): boolean {
  if (arr.length === 0) return false;
  return arr.every((x) => x && typeof x === "object" && (typeof (x as any).name === "string" || typeof (x as any).description === "string"));
}

function isValidTool(t: NormalizedTool): boolean {
  return t.name.length > 0;
}

function normalizeTool(raw: unknown): NormalizedTool {
  const obj = (raw ?? {}) as Record<string, unknown>;
  return {
    name: typeof obj.name === "string" ? obj.name : "",
    description: typeof obj.description === "string" ? obj.description : "",
    inputSchema: isPlainObject(obj.inputSchema) ? (obj.inputSchema as Record<string, unknown>) : {},
    outputSchema: isPlainObject(obj.outputSchema) ? (obj.outputSchema as Record<string, unknown>) : undefined,
    raw: obj,
  };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}

// Strip // and /* */ comments, but only outside strings. Simple but works for typical JSONC.
function stripJsonComments(text: string): string {
  let out = "";
  let i = 0;
  let inString = false;
  let escape = false;
  while (i < text.length) {
    const ch = text[i];
    const next = text[i + 1];
    if (inString) {
      out += ch;
      if (escape) { escape = false; }
      else if (ch === "\\") { escape = true; }
      else if (ch === '"') { inString = false; }
      i++;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      i++;
      continue;
    }
    if (ch === "/" && next === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}
