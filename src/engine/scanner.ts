// Tool Poisoning Scanner — static analysis for MCP tool definitions.
// Implements Layer 4 (L-RPE) "semantic validation" + MCP-Guard Stage-1 style
// pattern matching to detect TC1 (Tool Poisoning) and TC6 (Context Manipulation).

import type { Finding, MCPServer, MCPTool, ScanResult, Severity } from "./types";

interface Rule {
  rule: string;
  tv: string;
  severity: Severity;
  // returns matched evidence string(s)
  test: (text: string) => string[];
  message: string;
  recommendation: string;
  fields: ("name" | "description" | "schema")[];
}

const ri = (s: string) => new RegExp(s, "gi");

// Each rule scans tool text for adversarial / prompt-injection signatures.
const RULES: Rule[] = [
  {
    rule: "Hidden instruction directive",
    tv: "TV1",
    severity: "critical",
    fields: ["description", "schema"],
    message:
      "Imperative instructions aimed at the model were found inside a tool definition. Tool text is parsed by the LLM and can hijack agent behavior.",
    recommendation:
      "Remove model-directed instructions from descriptions. Descriptions should describe functionality, not command the agent.",
    test: matchAny([
      ri("ignore (all |the |previous |above )?(instructions|prompts?|context)"),
      ri("disregard (all |the |previous |above )"),
      ri("do not (tell|inform|mention|reveal|notify) (the )?(user|anyone)"),
      ri("without (informing|telling|asking|notifying) the user"),
      ri("you (must|should|are required to|have to) (now |always )?(call|invoke|use|run)"),
      ri("before (using|calling) (this|any other) tool[, ]"),
      ri("\\bsystem prompt\\b"),
      ri("as an? (ai|assistant|agent),? you (must|should|will)"),
    ]),
  },
  {
    rule: "Data exfiltration intent",
    tv: "TV8",
    severity: "critical",
    fields: ["description", "schema"],
    message:
      "Language suggesting the tool collects, forwards, or transmits sensitive data to an external destination (Log-to-Leak pattern).",
    recommendation:
      "Verify the tool's actual network behavior. Block tools that request reading credentials/keys and sending them elsewhere.",
    test: matchAny([
      ri("(send|forward|post|upload|transmit|exfiltrate)[^.]{0,40}(to )?(http|https|api|server|endpoint|url|webhook)"),
      ri("(read|collect|gather|access)[^.]{0,40}(api[_ ]?key|password|secret|token|credential|ssh|\\.env|private key)"),
      ri("(chat history|conversation|messages|contacts|emails?)[^.]{0,40}(send|forward|export)"),
      ri("base64|hex[- ]?encode"),
      ri("(include|append|attach)[^.]{0,30}(in|to)[^.]{0,20}(the )?(url|query|params?)"),
    ]),
  },
  {
    rule: "Credential / secret reference",
    tv: "TV18",
    severity: "high",
    fields: ["description", "schema", "name"],
    message:
      "References to credentials or secret-bearing files. Tools should never need raw secrets in their descriptions or parameters.",
    recommendation:
      "Confirm secrets are handled via a vault, never passed as plain tool arguments. Apply least-privilege scopes (L-CAC).",
    test: matchAny([
      ri("\\b(api[_ ]?key|secret[_ ]?key|access[_ ]?token|private[_ ]?key)\\b"),
      ri("~?/\\.ssh|id_rsa|\\.env|\\.aws/credentials|\\.npmrc"),
      ri("\\bpassword\\b|\\bpasswd\\b"),
    ]),
  },
  {
    rule: "Hidden/invisible content",
    tv: "TV1",
    severity: "high",
    fields: ["description", "schema"],
    message:
      "Zero-width characters, HTML comments, or invisible markup detected — a classic technique to hide instructions from humans while the LLM still reads them.",
    recommendation:
      "Strip non-printable characters and markup from tool text before presenting it to the model.",
    test: (text) => {
      const out: string[] = [];
      if (/[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/.test(text)) out.push("zero-width / bidi control characters");
      if (/<!--[\s\S]*?-->/.test(text)) out.push("HTML comment");
      if (/<[^>]+style=["'][^"']*(display\s*:\s*none|font-size\s*:\s*0)/i.test(text))
        out.push("hidden HTML element");
      return out;
    },
  },
  {
    rule: "Tool-shadowing / override language",
    tv: "TV4",
    severity: "high",
    fields: ["description"],
    message:
      "Description attempts to redirect, override, or replace another tool — indicative of tool shadowing.",
    recommendation:
      "Enforce unique, namespaced tool names and cryptographic attestation (L-CTA) so shadow tools cannot impersonate trusted ones.",
    test: matchAny([
      ri("(instead of|rather than|in place of) (using |calling )?(the )?\\w+ tool"),
      ri("(override|replace|supersede|deprecat)[^.]{0,30}tool"),
      ri("this is the (only|real|official|correct|preferred) (version of the )?tool"),
      ri("redirect (all )?(calls|requests|invocations)"),
    ]),
  },
  {
    rule: "Consent / approval bypass",
    tv: "TV13",
    severity: "high",
    fields: ["description", "schema"],
    message:
      "Language pushing the agent to auto-approve, skip confirmation, or act silently — a consent-bypass attempt.",
    recommendation:
      "Force human-in-the-loop confirmation for write/execute scopes regardless of tool text (L-RPE consent enforcement).",
    test: matchAny([
      ri("(auto[- ]?approve|automatically (approve|confirm|accept))"),
      ri("(no|without|skip)[^.]{0,20}(confirmation|approval|consent|permission)"),
      ri("(silently|quietly|in the background)[^.]{0,20}(run|execute|call|perform)"),
      ri("do(es)? not (require|need) (user )?(approval|confirmation|consent)"),
    ]),
  },
  {
    rule: "Command / code execution surface",
    tv: "TV18",
    severity: "medium",
    fields: ["description", "name", "schema"],
    message:
      "Tool exposes shell, eval, or arbitrary code execution. High-impact capability that requires strict scoping.",
    recommendation:
      "Gate execution tools behind explicit capabilities, composition rules, and rate limits. Never auto-approve.",
    test: matchAny([
      ri("\\b(exec|eval|system call|shell|bash|powershell|subprocess|os\\.system|child_process)\\b"),
      ri("(run|execute) (arbitrary )?(code|command|script)"),
    ]),
  },
  {
    rule: "Insecure transport coercion",
    tv: "TV10",
    severity: "medium",
    fields: ["description", "schema"],
    message:
      "Tool references plain HTTP or unencrypted channels for data transfer.",
    recommendation:
      "Require TLS/HTTPS for all external transfers; reject downgrade to http:// or unencrypted stdio bridges.",
    test: matchAny([ri("http://(?!localhost|127\\.0\\.0\\.1)"), ri("unencrypted|plaintext|cleartext")]),
  },
  {
    rule: "Hidden schema parameter",
    tv: "TV2",
    severity: "medium",
    fields: ["schema"],
    message:
      "Schema contains suspiciously named hidden/internal/debug parameters that may trigger undisclosed side effects.",
    recommendation:
      "Audit every parameter. Reject params not documented in the human-readable interface (schema manipulation, TV2).",
    test: matchAny([
      ri('"(__|_internal|_hidden|debug|admin|sudo|override|bypass|raw)\\w*"'),
    ]),
  },
  {
    rule: "Urgency / social-engineering pressure",
    tv: "TV18",
    severity: "low",
    fields: ["description"],
    message:
      "Pressure or urgency language ('immediately', 'critical', 'you will fail') used to coerce the agent.",
    recommendation:
      "Treat urgency cues in tool text as adversarial signals; they have no legitimate place in a functional description.",
    test: matchAny([
      ri("(immediately|right now|urgent(ly)?|critical(ly)?|asap)"),
      ri("you (will|would) (fail|be (penalized|punished|wrong))"),
      ri("it is (very |extremely )?important that you"),
    ]),
  },
  {
    rule: "File system traversal",
    tv: "TV18",
    severity: "high",
    fields: ["description", "schema"],
    message:
      "Tool description or schema references path traversal patterns or sensitive system directories.",
    recommendation:
      "Constrain file access to an explicit allowlist of directories. Never allow tools to access /, ~, or system paths without scoping.",
    test: matchAny([
      ri("\\.\\.[\\\\/]"),
      ri("[\\\\/]etc[\\\\/](passwd|shadow|hosts)"),
      ri("[\\\\/](root|home[\\\\/]\\w+)[\\\\/]\\.(bash|zsh|profile|ssh)"),
      ri("~[\\\\/]\\."),
      ri("(read|write|access|modify|delete)[^.]{0,30}(any|all|every|arbitrary) file"),
    ]),
  },
  {
    rule: "Network reconnaissance",
    tv: "TV18",
    severity: "medium",
    fields: ["description", "schema"],
    message:
      "Tool appears to perform network scanning, port probing, or DNS enumeration — high-risk capabilities.",
    recommendation:
      "Network tools require explicit execute capabilities and human confirmation per invocation.",
    test: matchAny([
      ri("\\b(nmap|port[- ]?scan|network[- ]?scan|dns[- ]?enum|traceroute|ping sweep)\\b"),
      ri("scan (all |open )?(ports|hosts|network|subnet)"),
    ]),
  },
  {
    rule: "Obfuscated content",
    tv: "TV1",
    severity: "high",
    fields: ["description", "schema"],
    message:
      "Possible obfuscation: base64 blobs, hex-encoded strings, or unicode escaping in tool text — may hide malicious instructions.",
    recommendation:
      "Decode and inspect all encoded content in tool definitions before allowing use.",
    test: (text) => {
      const out: string[] = [];
      // base64 block (40+ chars of base64 alphabet)
      const b64 = text.match(/[A-Za-z0-9+/=]{40,}/);
      if (b64) out.push(`base64 blob: ${b64[0].slice(0, 30)}...`);
      // long hex string
      const hex = text.match(/(?:0x)?[0-9a-fA-F]{32,}/);
      if (hex) out.push(`hex string: ${hex[0].slice(0, 30)}...`);
      // excessive unicode escapes
      const uc = text.match(/\\u[0-9a-fA-F]{4}/g);
      if (uc && uc.length >= 4) out.push(`${uc.length} unicode escapes`);
      return out;
    },
  },
  {
    rule: "Dangerous environment variable exposure",
    tv: "TV18",
    severity: "high",
    fields: ["description", "schema"],
    message:
      "Config exposes environment variables containing secrets (API keys, tokens, passwords).",
    recommendation:
      "Use a secrets manager or vault. Never embed raw secrets in MCP server configs — rotate any exposed keys immediately.",
    test: matchAny([
      ri("(OPENAI|ANTHROPIC|GITHUB|AWS|AZURE|GCP|STRIPE|SLACK|DISCORD)[_\\s]?(API)?[_\\s]?(KEY|TOKEN|SECRET)"),
      ri("(DATABASE|REDIS|MONGO|POSTGRES|MYSQL)[_\\s]?(URL|URI|PASSWORD|CONNECTION)"),
      ri("(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|gho_[a-zA-Z0-9]{20,})"),
      ri("(xoxb-|xoxp-|xapp-)[a-zA-Z0-9\\-]{20,}"),
      ri("AKIA[0-9A-Z]{16}"),
    ]),
  },
  {
    rule: "Excessive permissions / wildcards",
    tv: "TV13",
    severity: "medium",
    fields: ["description", "schema"],
    message:
      "Tool claims or requests full/wildcard access — violates least privilege.",
    recommendation:
      "Define explicit, narrow capability scopes. Reject any tool claiming '*' or 'all' permissions.",
    test: matchAny([
      ri("(full|complete|unrestricted|unlimited|root|admin|sudo) (access|permissions?|privileges?)"),
      ri('(scope|permission|access)["\']?\\s*:\\s*["\']?\\*'),
    ]),
  },
];

function matchAny(regexes: RegExp[]) {
  return (text: string): string[] => {
    const out: string[] = [];
    for (const re of regexes) {
      re.lastIndex = 0;
      const m = re.exec(text);
      if (m) out.push(snippet(text, m.index, m[0].length));
    }
    return out;
  };
}

function snippet(text: string, index: number, len: number): string {
  const start = Math.max(0, index - 24);
  const end = Math.min(text.length, index + len + 24);
  let s = text.slice(start, end).replace(/\s+/g, " ").trim();
  if (start > 0) s = "…" + s;
  if (end < text.length) s = s + "…";
  return s;
}

function schemaText(tool: MCPTool): string {
  try {
    return JSON.stringify(tool.inputSchema ?? {}) + " " + JSON.stringify(tool.annotations ?? {});
  } catch {
    return "";
  }
}

let counter = 0;

export function scanTool(tool: MCPTool): Finding[] {
  const findings: Finding[] = [];
  const name = tool.name ?? "";
  const desc = tool.description ?? "";
  const schema = schemaText(tool);

  for (const rule of RULES) {
    const fieldTexts: { field: string; text: string }[] = [];
    if (rule.fields.includes("name")) fieldTexts.push({ field: "name", text: name });
    if (rule.fields.includes("description")) fieldTexts.push({ field: "description", text: desc });
    if (rule.fields.includes("schema")) fieldTexts.push({ field: "schema", text: schema });

    for (const { field, text } of fieldTexts) {
      const hits = rule.test(text);
      for (const evidence of hits) {
        findings.push({
          id: `F${++counter}`,
          rule: rule.rule,
          tv: rule.tv,
          severity: rule.severity,
          toolName: name || "(unnamed tool)",
          field,
          message: rule.message,
          evidence,
          recommendation: rule.recommendation,
        });
      }
    }
  }
  return dedupe(findings);
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.toolName}|${f.rule}|${f.field}|${f.evidence}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 1,
};

export function scanServer(server: MCPServer): ScanResult {
  const findings = server.tools.flatMap(scanTool);
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let raw = 0;
  for (const f of findings) {
    counts[f.severity]++;
    raw += SEVERITY_WEIGHT[f.severity];
  }
  const score = Math.min(100, raw);
  const grade: ScanResult["grade"] =
    score === 0 ? "A" : score < 15 ? "B" : score < 35 ? "C" : score < 60 ? "D" : "F";

  return {
    findings,
    score,
    grade,
    toolCount: server.tools.length,
    scannedAt: Date.now(),
    counts,
  };
}
