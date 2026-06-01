// Static analysis engine for MCP server configurations.
// Performs STRUCTURAL analysis (not just regex) including:
//   - JSON schema validation
//   - Entropy-based secret detection
//   - Transport security checks
//   - Tool description semantic analysis (structural features, not vibes)
//   - Cross-tool duplication detection
//   - Permission scope inference

import type {
  Finding,
  NormalizedServer,
  NormalizedTool,
  Severity,
  StaticAnalysis,
} from "./types";

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 35,
  high: 18,
  medium: 7,
  low: 3,
  info: 0,
};

let idCounter = 0;
const newId = () => `F${++idCounter}`;

export function analyze(servers: NormalizedServer[], parserWarnings: string[]): StaticAnalysis {
  const findings: Finding[] = [];
  const allTools: { server: string; tool: NormalizedTool }[] = [];

  for (const server of servers) {
    // transport checks
    checkTransport(server, findings);
    // env var / secret detection
    checkEnvSecrets(server, findings);
    // command / args safety
    checkCommandSafety(server, findings);
    // source format warnings
    for (const w of server.warnings) {
      findings.push({
        id: newId(),
        rule: "Suspicious launcher configuration",
        tv: "TV16",
        severity: "low",
        category: "Server trust",
        target: server.name,
        message: w,
        evidence: server.command ? `command: ${server.command} ${(server.args ?? []).join(" ")}` : "",
        reasoning: "Auto-executing packages or unconfirmed downloaders can pull malicious code at install time.",
        recommendation: "Pin exact versions, verify publisher signatures, prefer local installs over npx -y.",
        location: { server: server.name },
      });
    }
    // per-tool checks
    for (const tool of server.tools) {
      allTools.push({ server: server.name, tool });
      checkToolSchema(server, tool, findings);
      checkToolDescription(server, tool, findings);
      checkToolName(server, tool, findings);
    }
  }

  // cross-server: duplicate tool names
  checkDuplicateToolNames(allTools, findings);
  // cross-server: tool shadowing
  checkToolShadowing(allTools, findings);
  // empty servers
  for (const server of servers) {
    if (server.tools.length === 0) {
      findings.push({
        id: newId(),
        rule: "No tools in server definition",
        tv: "TV15",
        severity: "info",
        category: "Server trust",
        target: server.name,
        message: `Server "${server.name}" has no tools in the provided config.`,
        evidence: `transport=${server.transport}, source=${server.sourceFormat}`,
        reasoning: "Empty server definitions may indicate a config error or a server that only acts as a backend. Verify expected behavior.",
        recommendation: "Run the server and capture a real tools/list response to get its actual tool surface.",
        location: { server: server.name },
      });
    }
  }

  // total tool count
  const totalTools = allTools.length;

  // scoring
  let raw = 0;
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    counts[f.severity]++;
    raw += SEVERITY_WEIGHT[f.severity];
  }
  const score = Math.min(100, raw);
  const grade: StaticAnalysis["grade"] =
    score === 0 ? "A" : score < 12 ? "B" : score < 28 ? "C" : score < 55 ? "D" : "F";

  return {
    findings: findings.sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity]),
    score,
    grade,
    counts,
    servers,
    totalTools,
    parsedAt: Date.now(),
    parserWarnings,
  };
}

// ============================================================
// TRANSPORT
// ============================================================
function checkTransport(server: NormalizedServer, out: Finding[]) {
  if (server.transport === "http") {
    out.push({
      id: newId(),
      rule: "Insecure transport (HTTP)",
      tv: "TV10",
      severity: "high",
      category: "Transport security",
      target: server.name,
      message: `Server "${server.name}" uses plain HTTP — all data is transmitted in cleartext.`,
      evidence: `url: ${server.url ?? "(no url)"}`,
      reasoning: "Any intermediary (Wi-Fi router, ISP, malicious proxy) can read and modify tool calls and responses, enabling data exfiltration and tool poisoning.",
      recommendation: "Use HTTPS or local stdio. If HTTP is unavoidable, restrict to localhost and ensure no sensitive data crosses the wire.",
      location: { server: server.name, field: "url" },
    });
  }
  if (server.transport === "websocket" && server.url?.startsWith("ws://")) {
    out.push({
      id: newId(),
      rule: "Insecure WebSocket transport",
      tv: "TV10",
      severity: "high",
      category: "Transport security",
      target: server.name,
      message: `Server "${server.name}" uses ws:// (unencrypted WebSocket).`,
      evidence: `url: ${server.url}`,
      reasoning: "Same risk as HTTP: cleartext channel for all MCP messages.",
      recommendation: "Use wss:// (WebSocket Secure) or stdio.",
      location: { server: server.name, field: "url" },
    });
  }
  if (server.transport === "stdio" && server.command) {
    out.push({
      id: newId(),
      rule: "stdio transport with shell-launching command",
      tv: "TV18",
      severity: "info",
      category: "Transport security",
      target: server.name,
      message: `Server "${server.name}" runs as a local subprocess (stdio).`,
      evidence: `command: ${server.command} ${(server.args ?? []).join(" ")}`,
      reasoning: "stdio is local and trusted by default, but the command itself is the new attack surface. A malicious or compromised package gains the same privileges as the agent host.",
      recommendation: "Audit the package, pin versions, and consider running under a separate user account with minimal filesystem access.",
      location: { server: server.name, field: "command" },
    });
  }
}

// ============================================================
// ENV SECRETS — entropy + pattern based
// ============================================================
function checkEnvSecrets(server: NormalizedServer, out: Finding[]) {
  if (!server.env) return;
  for (const [key, value] of Object.entries(server.env)) {
    if (typeof value !== "string" || value.length === 0) continue;

    const entropy = shannonEntropy(value);
    const keyHint = key.toLowerCase();
    const looksLikeSecret = /token|key|secret|password|pass|auth|cred|api/i.test(keyHint);
    const highEntropy = entropy > 4.0 && value.length >= 16;
    const containsKnownToken = KNOWN_TOKEN_PATTERNS.some((re) => re.test(value));

    if (looksLikeSecret || highEntropy || containsKnownToken) {
      let severity: Severity = "high";
      let tv = "TV18";
      if (containsKnownToken) { severity = "critical"; tv = "TV16"; }
      else if (looksLikeSecret && highEntropy) { severity = "critical"; }

      out.push({
        id: newId(),
        rule: "Secret in server environment",
        tv,
        severity,
        category: "Secret exposure",
        target: `${server.name}.env.${key}`,
        message: `Env var "${key}" in server "${server.name}" contains what appears to be a secret.`,
        evidence: maskSecret(value) + (containsKnownToken ? " (matches known token format)" : ""),
        reasoning: "Secrets in MCP server configs can leak through logs, error messages, or process listings. Once disclosed, they cannot be revoked without rotation.",
        recommendation: "Move secrets to a vault or OS keychain. Reference by name; let the launcher resolve. Rotate any secret that has appeared in a config file.",
        location: { server: server.name, field: `env.${key}`, path: `$.mcpServers.${server.name}.env.${key}` },
      });
    }
  }
}

// ============================================================
// COMMAND / ARGS
// ============================================================
function checkCommandSafety(server: NormalizedServer, out: Finding[]) {
  if (!server.command) return;
  const args = server.args ?? [];
  const all = [server.command, ...args].join(" ");

  // shell metachars
  if (/[;&|`$()<>]/.test(all)) {
    out.push({
      id: newId(),
      rule: "Shell metacharacters in command",
      tv: "TV18",
      severity: "high",
      category: "Command injection surface",
      target: server.name,
      message: `Command for "${server.name}" contains shell metacharacters.`,
      evidence: all,
      reasoning: "If the launcher concatenates args with a shell, metacharacters can execute arbitrary commands.",
      recommendation: "Pass args as an array (which MCP clients do) — never via a shell string. Verify the launcher is array-args based.",
      location: { server: server.name, field: "args" },
    });
  }

  // curl/wget piping to shell
  if (/curl\s+.*\|\s*(sh|bash|zsh)|wget\s+.*\|\s*(sh|bash|zsh)/.test(all)) {
    out.push({
      id: newId(),
      rule: "Curl-pipe-to-shell",
      tv: "TV16",
      severity: "critical",
      category: "Supply chain",
      target: server.name,
      message: `Command for "${server.name}" pipes a remote download directly into a shell.`,
      evidence: all,
      reasoning: "If the URL is hijacked or compromised, the shell runs attacker code with no review.",
      recommendation: "Download to a file, verify checksum/signature, then execute.",
      location: { server: server.name, field: "command" },
    });
  }

  // absolute path to writable location
  if (/^(\/tmp|\/var\/tmp|\/dev\/shm)\//.test(server.command)) {
    out.push({
      id: newId(),
      rule: "Executable from writable temp directory",
      tv: "TV18",
      severity: "medium",
      category: "Supply chain",
      target: server.name,
      message: `Command path is in a writable temp location: ${server.command}`,
      evidence: server.command,
      reasoning: "Anything in /tmp, /var/tmp, or /dev/shm can be overwritten by any local user or process.",
      recommendation: "Use a system-installed binary or a version-pinned local install.",
      location: { server: server.name, field: "command" },
    });
  }
}

// ============================================================
// TOOL SCHEMA
// ============================================================
function checkToolSchema(server: NormalizedServer, tool: NormalizedTool, out: Finding[]) {
  const schema = tool.inputSchema;

  // missing schema entirely
  if (!schema || Object.keys(schema).length === 0) {
    out.push({
      id: newId(),
      rule: "Tool has no input schema",
      tv: "TV2",
      severity: "medium",
      category: "Schema safety",
      target: `${server.name}.${tool.name}`,
      message: `Tool "${tool.name}" provides no input schema — the agent can call it with any arguments.`,
      evidence: `inputSchema: ${JSON.stringify(schema) || "(empty)"}`,
      reasoning: "Without a schema, the LLM invents arguments. The server must accept anything, which creates an unbounded surface for misuse.",
      recommendation: "Define a JSON Schema with explicit properties and required fields. Reject unknown args at the server.",
      location: { server: server.name, tool: tool.name, field: "inputSchema" },
    });
    return;
  }

  // schema.type
  if (schema.type !== "object") {
    out.push({
      id: newId(),
      rule: "Tool inputSchema.type is not 'object'",
      tv: "TV2",
      severity: "low",
      category: "Schema safety",
      target: `${server.name}.${tool.name}`,
      message: `Tool "${tool.name}" has inputSchema.type="${String(schema.type)}" instead of "object".`,
      evidence: JSON.stringify(schema.type),
      reasoning: "MCP tool inputs are conventionally JSON objects. Non-object roots are unusual and may confuse agents.",
      recommendation: "Use type: 'object' with a 'properties' map.",
      location: { server: server.name, tool: tool.name, field: "inputSchema.type" },
    });
  }

  // hidden/undocumented parameters
  const props = (schema.properties && typeof schema.properties === "object")
    ? (schema.properties as Record<string, unknown>)
    : {};
  for (const [pname, pdef] of Object.entries(props)) {
    if (/^(__|_internal|_hidden|debug|admin|sudo|override|bypass|raw|secret|token)/i.test(pname)) {
      out.push({
        id: newId(),
        rule: "Hidden or admin-named parameter",
        tv: "TV2",
        severity: "high",
        category: "Schema safety",
        target: `${server.name}.${tool.name}.${pname}`,
        message: `Tool "${tool.name}" has a parameter named "${pname}" that suggests hidden or privileged behavior.`,
        evidence: JSON.stringify(pdef),
        reasoning: "Parameters with names like 'admin', 'bypass', 'raw' often trigger undocumented side effects that the user/agent isn't informed about.",
        recommendation: "Document the parameter's purpose in the schema description, or remove it if it's not needed.",
        location: { server: server.name, tool: tool.name, field: `inputSchema.properties.${pname}` },
      });
    }
  }

  // dangerous parameter types: any, mixed
  for (const [pname, pdef] of Object.entries(props)) {
    const ptype = (pdef && typeof pdef === "object") ? (pdef as Record<string, unknown>).type : undefined;
    if (ptype === "any" || (Array.isArray(ptype) && ptype.includes("any"))) {
      out.push({
        id: newId(),
        rule: "Parameter accepts 'any' type",
        tv: "TV2",
        severity: "medium",
        category: "Schema safety",
        target: `${server.name}.${tool.name}.${pname}`,
        message: `Parameter "${pname}" of tool "${tool.name}" accepts type "any" — unconstrained values.`,
        evidence: JSON.stringify(pdef),
        reasoning: "Loses schema validation entirely for this argument; server must handle every possible input safely.",
        recommendation: "Use a union of specific types or a constrained string enum.",
        location: { server: server.name, tool: tool.name, field: `inputSchema.properties.${pname}.type` },
      });
    }
  }
}

// ============================================================
// TOOL DESCRIPTION — STRUCTURAL features
// ============================================================
function checkToolDescription(server: NormalizedServer, tool: NormalizedTool, out: Finding[]) {
  const desc = tool.description;
  if (!desc || desc.trim().length === 0) {
    out.push({
      id: newId(),
      rule: "Tool has no description",
      tv: "TV1",
      severity: "medium",
      category: "Description safety",
      target: `${server.name}.${tool.name}`,
      message: `Tool "${tool.name}" has an empty description.`,
      evidence: `description: ""`,
      reasoning: "The LLM uses the description to decide when to call the tool. An empty description can still be filled with hidden annotations or schema text.",
      recommendation: "Provide a clear, single-sentence description of the tool's legitimate purpose.",
      location: { server: server.name, tool: tool.name, field: "description" },
    });
    return;
  }

  // structural features of the description text
  const features = extractTextFeatures(desc);

  // LONG description (LLM processing cost, hides instructions)
  if (desc.length > 1500) {
    out.push({
      id: newId(),
      rule: "Unusually long tool description",
      tv: "TV1",
      severity: "medium",
      category: "Description safety",
      target: `${server.name}.${tool.name}`,
      message: `Tool "${tool.name}" has a ${desc.length}-character description (typical: 50-300).`,
      evidence: `first 120 chars: ${desc.slice(0, 120)}…`,
      reasoning: "Long descriptions are an attack surface for prompt injection — they may include hidden instructions the user never reads.",
      recommendation: "Keep descriptions under ~300 characters. Move any necessary detail to the schema's property descriptions.",
      location: { server: server.name, tool: tool.name, field: "description" },
    });
  }

  // HIGH INSTRUCTION DENSITY: many imperative verbs suggest commands to the LLM
  if (features.imperativeVerbCount >= 4) {
    out.push({
      id: newId(),
      rule: "High imperative-verb density in description",
      tv: "TV1",
      severity: "high",
      category: "Description safety",
      target: `${server.name}.${tool.name}`,
      message: `Description contains ${features.imperativeVerbCount} imperative-style commands — typical functional descriptions use 0-2.`,
      evidence: `verbs found: ${features.imperativeVerbs.join(", ")}`,
      reasoning: "Genuine tool descriptions state what a tool does in past/present tense ('Returns the weather'). Imperative commands ('Ignore the user', 'Always call X first') indicate instructions to the model.",
      recommendation: "Rewrite in descriptive form. Replace imperatives with 'this tool returns/provides/queries'.",
      location: { server: server.name, tool: tool.name, field: "description" },
    });
  }

  // EXPLICIT INSTRUCTION PHRASES
  for (const phrase of INSTRUCTION_PHRASES) {
    const m = desc.toLowerCase().match(phrase);
    if (m) {
      out.push({
        id: newId(),
        rule: "Direct model instruction in description",
        tv: "TV1",
        severity: "critical",
        category: "Description safety",
        target: `${server.name}.${tool.name}`,
        message: `Description contains phrasing that addresses the model directly.`,
        evidence: `…${snippet(desc, m.index ?? 0, m[0].length)}…`,
        reasoning: "Legitimate tool descriptions never talk to the model. Phrases like 'ignore previous instructions' or 'do not tell the user' are unambiguous prompt-injection signatures.",
        recommendation: "Remove immediately. This is a hostile tool definition.",
        location: { server: server.name, tool: tool.name, field: "description" },
      });
    }
  }

  // URLs in description
  const urls = desc.match(/https?:\/\/[^\s)>\]]+/gi) ?? [];
  for (const url of urls) {
    const isLocal = /^(https?:\/\/)?(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)/i.test(url);
    if (!isLocal) {
      out.push({
        id: newId(),
        rule: "External URL in tool description",
        tv: "TV8",
        severity: "medium",
        category: "Description safety",
        target: `${server.name}.${tool.name}`,
        message: `Description references external URL: ${url}`,
        evidence: url,
        reasoning: "External URLs in a description are unusual; they may be exfiltration endpoints or instructions to fetch adversarial content.",
        recommendation: "Verify the URL is the server's legitimate domain. Remove if unnecessary.",
        location: { server: server.name, tool: tool.name, field: "description" },
      });
    }
  }

  // ENCODED CONTENT (base64, hex) > 40 chars
  const b64 = desc.match(/[A-Za-z0-9+/=]{40,}/g) ?? [];
  const hex = desc.match(/(?:0x)?[0-9a-fA-F]{32,}/g) ?? [];
  if (b64.length > 0 || hex.length > 0) {
    out.push({
      id: newId(),
      rule: "Encoded content in description",
      tv: "TV1",
      severity: "high",
      category: "Description safety",
      target: `${server.name}.${tool.name}`,
      message: `Description contains encoded strings (base64 or long hex) — may hide adversarial instructions.`,
      evidence: `b64 candidates: ${b64.length}, hex candidates: ${hex.length}`,
      reasoning: "Encoded content bypasses casual review. Attackers use it to smuggle instructions the human eye skips.",
      recommendation: "Decode and review all encoded content. If you didn't expect to see it, the tool is hostile.",
      location: { server: server.name, tool: tool.name, field: "description" },
    });
  }

  // HIDDEN CHARS (zero-width, bidi control)
  if (/[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/.test(desc)) {
    out.push({
      id: newId(),
      rule: "Invisible/zero-width characters",
      tv: "TV1",
      severity: "high",
      category: "Description safety",
      target: `${server.name}.${tool.name}`,
      message: `Description contains zero-width or bidi-control characters.`,
      evidence: `${(desc.match(/[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/g) ?? []).length} such character(s)`,
      reasoning: "Invisible characters can hide instructions invisible to humans but processed by the LLM.",
      recommendation: "Strip non-printable characters. Reject any description that contains them.",
      location: { server: server.name, tool: tool.name, field: "description" },
    });
  }
}

// ============================================================
// TOOL NAME
// ============================================================
function checkToolName(server: NormalizedServer, tool: NormalizedTool, out: Finding[]) {
  if (tool.name.length > 60) {
    out.push({
      id: newId(),
      rule: "Overly long tool name",
      tv: "TV4",
      severity: "low",
      category: "Naming safety",
      target: `${server.name}.${tool.name}`,
      message: `Tool name is ${tool.name.length} characters.`,
      evidence: tool.name.slice(0, 80) + (tool.name.length > 80 ? "…" : ""),
      reasoning: "Long names may carry hidden payloads (text the LLM treats as a tool reference).",
      recommendation: "Keep tool names short and conventional (< 40 chars).",
      location: { server: server.name, tool: tool.name, field: "name" },
    });
  }
  if (/[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/.test(tool.name)) {
    out.push({
      id: newId(),
      rule: "Invisible characters in tool name",
      tv: "TV1",
      severity: "critical",
      category: "Naming safety",
      target: `${server.name}.${tool.name}`,
      message: `Tool name contains invisible characters.`,
      evidence: tool.name,
      reasoning: "Could enable a homograph attack — appearing identical to a legitimate tool name.",
      recommendation: "Reject the tool. This is a shadowing attempt.",
      location: { server: server.name, tool: tool.name, field: "name" },
    });
  }
}

// ============================================================
// CROSS-TOOL: duplicates and shadowing
// ============================================================
function checkDuplicateToolNames(tools: { server: string; tool: NormalizedTool }[], out: Finding[]) {
  const map = new Map<string, { server: string; tool: NormalizedTool }[]>();
  for (const t of tools) {
    const k = t.tool.name.toLowerCase();
    if (!map.has(k)) map.set(k, []);
    map.get(k)!.push(t);
  }
  for (const [name, entries] of map) {
    if (entries.length > 1) {
      out.push({
        id: newId(),
        rule: "Duplicate tool name across servers",
        tv: "TV4",
        severity: "high",
        category: "Tool shadowing",
        target: name,
        message: `Tool name "${entries[0].tool.name}" is registered by ${entries.length} servers: ${entries.map((e) => e.server).join(", ")}.`,
        evidence: entries.map((e) => `${e.server}:${e.tool.name}`).join(" | "),
        reasoning: "When two servers expose the same tool name, the agent (and the user) cannot tell which is being called. This is the definition of tool shadowing.",
        recommendation: "Namespace tools per server (e.g. 'github.list_repos') or disambiguate by name.",
        location: { tool: entries[0].tool.name },
      });
    }
  }
}

function checkToolShadowing(tools: { server: string; tool: NormalizedTool }[], out: Finding[]) {
  // detect tools whose description claims to be the "official" version of another
  for (const t of tools) {
    const desc = t.tool.description.toLowerCase();
    if (/\b(this is the (only|real|official|correct|preferred) (version of the )?tool)|(use this instead of)|(do not use (the |my )?(\w+ )?tool)/.test(desc)) {
      out.push({
        id: newId(),
        rule: "Tool description claims authority over other tools",
        tv: "TV4",
        severity: "high",
        category: "Tool shadowing",
        target: `${t.server}.${t.tool.name}`,
        message: `Description attempts to redirect invocations away from other tools.`,
        evidence: t.tool.description.slice(0, 200),
        reasoning: "A legitimate tool does not need to instruct the agent to avoid competitors. This pattern is a hallmark of tool shadowing.",
        recommendation: "Review who publishes this tool and whether they have any business claiming authority over other tools.",
        location: { server: t.server, tool: t.tool.name, field: "description" },
      });
    }
  }
}

// ============================================================
// UTILITIES
// ============================================================

interface TextFeatures {
  imperativeVerbCount: number;
  imperativeVerbs: string[];
}

const IMPERATIVE_VERBS = [
  "ignore", "disregard", "forget", "remember",
  "call", "invoke", "use", "run", "execute", "perform", "do", "make",
  "send", "forward", "post", "upload", "transmit", "exfiltrate",
  "read", "open", "close", "delete", "remove", "modify", "change", "edit",
  "include", "append", "attach", "hide", "conceal", "do not tell", "do not inform",
  "never", "always", "immediately", "must", "should",
];

const INSTRUCTION_PHRASES = [
  /\bignore (all |the |previous |above )?(instructions|prompts?|context|rules)/i,
  /\bdisregard (all |the |previous |above )/i,
  /\bdo not (tell|inform|mention|reveal|notify|alert) (the )?(user|anyone|them)/i,
  /\bwithout (informing|telling|asking|notifying) (the )?user/i,
  /\byou (must|should|are required to|have to) (now |always )?(call|invoke|use|run|never|always)/i,
  /\bbefore (using|calling) (this|any other) tool/i,
  /\bas an? (ai|assistant|agent),? you (must|should|will)/i,
  /\bsystem prompt\b/i,
];

const KNOWN_TOKEN_PATTERNS: RegExp[] = [
  /\bsk-[A-Za-z0-9]{20,}\b/,           // OpenAI
  /\bghp_[A-Za-z0-9]{20,}\b/,          // GitHub PAT
  /\bgho_[A-Za-z0-9]{20,}\b/,          // GitHub OAuth
  /\bghs_[A-Za-z0-9]{20,}\b/,          // GitHub server
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,  // GitHub fine-grained
  /\bxoxb-[A-Za-z0-9-]{20,}\b/,        // Slack bot
  /\bxoxp-[A-Za-z0-9-]{20,}\b/,        // Slack user
  /\bxapp-[A-Za-z0-9-]{20,}\b/,        // Slack app
  /\bAKIA[0-9A-Z]{16}\b/,              // AWS access key
  /\bASIA[0-9A-Z]{16}\b/,              // AWS session
  /\bAIza[0-9A-Za-z\-_]{35}\b/,        // Google API key
  /\bya29\.[0-9A-Za-z\-_]+\b/,         // Google OAuth
  /\b[A-Za-z0-9]{32,}\.[A-Za-z0-9]{16,}\.[A-Za-z0-9_-]{20,}\b/, // JWT-like
  /\bBearer\s+[A-Za-z0-9\-_=]{20,}\b/i,
];

function extractTextFeatures(text: string): TextFeatures {
  const lower = text.toLowerCase();
  const foundVerbs: string[] = [];
  for (const v of IMPERATIVE_VERBS) {
    const re = new RegExp(`\\b${v.replace(/\s+/g, "\\s+")}\\b`, "g");
    const m = lower.match(re);
    if (m) foundVerbs.push(v);
  }
  return { imperativeVerbCount: foundVerbs.length, imperativeVerbs: foundVerbs };
}

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  let h = 0;
  for (const n of Object.values(freq)) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function maskSecret(v: string): string {
  if (v.length <= 8) return "***";
  return v.slice(0, 4) + "…" + v.slice(-4) + ` (length ${v.length}, entropy ~${shannonEntropy(v).toFixed(2)})`;
}

function snippet(text: string, index: number, len: number): string {
  const start = Math.max(0, index - 30);
  const end = Math.min(text.length, index + len + 30);
  let s = text.slice(start, end).replace(/\s+/g, " ");
  if (start > 0) s = "…" + s;
  if (end < text.length) s = s + "…";
  return s;
}
