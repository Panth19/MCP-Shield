// MCPShield Proxy — a local middleware that sits between an MCP client
// (Claude Desktop, Cursor, etc.) and the user's MCP servers.
//
// Flow:
//   Client → http://localhost:PORT/mcp/<server-name>  →  Proxy
//                                                       ↓
//                                            Analyzes tools/list, tools/call
//                                            Forwards to upstream MCP server
//                                            Returns (possibly modified) result
//
// Modes:
//   - monitor: log everything, allow all (safe default)
//   - enforce: block calls based on policy + findings

import express, { type Request, type Response } from "express";
import cors from "cors";
import { spawn, type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { analyze, parseConfig, analyzeWithLLM, combineResults, loadConfig } from "./analyzer";
import type { AnalysisResult, NormalizedServer } from "../engine/types";

export interface ProxyConfig {
  port: number;
  upstream: Record<string, UpstreamConfig>; // server-name → how to reach it
  mode: "monitor" | "enforce";
  llm: { enabled: boolean; model?: string; baseUrl?: string };
  blockOnSeverity: ("critical" | "high" | "medium")[];
  scanOnList: boolean;     // analyze tools/list responses
  blockOnCall: boolean;    // analyze tools/call args too
  allowList: string[];     // tool names that bypass checks (e.g. trusted ones)
  persist: { path: string };
}

export type UpstreamConfig =
  | { kind: "stdio"; command: string; args: string[]; env?: Record<string, string> }
  | { kind: "http"; url: string; headers?: Record<string, string> };

interface StdioSession {
  proc: ChildProcess;
  pending: Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>;
  buffer: string;
  serverName: string;
  tools: any[]; // last known tool list
  analysis?: AnalysisResult;
  lastScanAt: number;
}

interface CallLog {
  id: string;
  timestamp: number;
  server: string;
  method: string;
  tool?: string;
  args?: unknown;
  decision: "allowed" | "blocked" | "modified" | "error";
  reasons: string[];
  durationMs: number;
  findingIds: string[];
}

export class MCPShieldProxy extends EventEmitter {
  private app: express.Express;
  private stdioSessions = new Map<string, StdioSession>();
  private callLog: CallLog[] = [];
  private readonly config: ProxyConfig;

  constructor(config: ProxyConfig) {
    super();
    this.config = config;
    this.app = express();
    this.app.use(cors());
    this.app.use(express.json({ limit: "10mb" }));

    this.setupRoutes();
  }

  // ============================================================
  // ROUTES
  // ============================================================
  private setupRoutes() {
    // Health check
    this.app.get("/health", (_req, res) => {
      res.json({
        status: "ok",
        mode: this.config.mode,
        servers: Object.keys(this.config.upstream),
        uptime: process.uptime(),
      });
    });

    // Live findings dashboard
    this.app.get("/dashboard", (_req, res) => {
      res.setHeader("Content-Type", "text/html");
      res.send(this.renderDashboard());
    });

    // API: current findings (per server)
    this.app.get("/api/findings", (_req, res) => {
      const all: { server: string; analysis: AnalysisResult | null; tools: number }[] = [];
      for (const [name, sess] of this.stdioSessions) {
        all.push({ server: name, analysis: sess.analysis ?? null, tools: sess.tools.length });
      }
      res.json({ servers: all, mode: this.config.mode, totalCalls: this.callLog.length });
    });

    // API: call log
    this.app.get("/api/log", (_req, res) => {
      res.json({ calls: this.callLog.slice(-100) });
    });

    // API: re-scan a server
    this.app.post("/api/rescan/:server", async (req, res) => {
      const name = String(req.params.server);
      const sess = this.stdioSessions.get(name);
      if (!sess) return res.status(404).json({ error: "Server not found or not yet connected" });
      await this.scanServer(sess);
      res.json({ ok: true, analysis: sess.analysis });
    });

    // MCP proxy endpoint:
    //   POST /mcp/<server-name>  { jsonrpc, id, method, params }
    this.app.post("/mcp/:server", async (req: Request, res: Response) => {
      const serverName = String(req.params.server);
      const upstream = this.config.upstream[serverName];
      if (!upstream) {
        return res.status(404).json({
          jsonrpc: "2.0",
          id: req.body?.id ?? null,
          error: { code: -32000, message: `Unknown upstream server "${serverName}"` },
        });
      }

      const start = performance.now();
      const body = req.body as { jsonrpc: string; id: number; method: string; params: any };

      // Pre-call checks (for tools/call)
      if (this.config.blockOnCall && body.method === "tools/call") {
        const toolName = body.params?.name;
        const args = body.params?.arguments;
        const decision = this.evaluateCall(serverName, toolName, args);
        if (!decision.allowed) {
          this.log({
            id: randomUUID(),
            timestamp: Date.now(),
            server: serverName,
            method: body.method,
            tool: toolName,
            args,
            decision: "blocked",
            reasons: decision.reasons,
            durationMs: Math.round(performance.now() - start),
            findingIds: decision.findingIds,
          });
          return res.json({
            jsonrpc: "2.0",
            id: body.id,
            error: {
              code: -32001,
              message: `MCPShield blocked this call: ${decision.reasons.join("; ")}`,
            },
          });
        }
      }

      try {
        // Forward to upstream
        const result = await this.forward(serverName, upstream, body);
        const durationMs = Math.round(performance.now() - start);

        // Post-call: if this was tools/list, analyze the tools and store
        if (body.method === "tools/list" && result && typeof result === "object" && "tools" in (result as any)) {
          const sess = this.getOrCreateStdioSession(serverName, upstream);
          sess.tools = (result as any).tools;
          if (this.config.scanOnList) {
            await this.scanServer(sess);
          }
        }

        // Post-call: if this was tools/call, log
        if (body.method === "tools/call") {
          this.log({
            id: randomUUID(),
            timestamp: Date.now(),
            server: serverName,
            method: body.method,
            tool: body.params?.name,
            args: body.params?.arguments,
            decision: "allowed",
            reasons: [],
            durationMs,
            findingIds: [],
          });
        }

        res.json({ jsonrpc: "2.0", id: body.id, result });
      } catch (e) {
        const msg = (e as Error).message;
        this.log({
          id: randomUUID(),
          timestamp: Date.now(),
          server: serverName,
          method: body.method,
          decision: "error",
          reasons: [msg],
          durationMs: Math.round(performance.now() - start),
          findingIds: [],
        });
        res.status(502).json({
          jsonrpc: "2.0",
          id: body.id,
          error: { code: -32002, message: `Upstream error: ${msg}` },
        });
      }
    });

    // Catch-all 404
    this.app.use((_req, res) => res.status(404).json({ error: "Not found" }));
  }

  // ============================================================
  // UPSTREAM FORWARDING
  // ============================================================
  private async forward(serverName: string, upstream: UpstreamConfig, msg: any): Promise<unknown> {
    if (upstream.kind === "http") {
      const res = await fetch(upstream.url, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(upstream.headers ?? {}) },
        body: JSON.stringify(msg),
        signal: AbortSignal.timeout(30000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} from upstream`);
      const data = await res.json();
      if (data.error) throw new Error(data.error.message ?? "Upstream JSON-RPC error");
      return data.result;
    } else {
      // stdio
      return this.forwardStdio(serverName, msg);
    }
  }

  private forwardStdio(serverName: string, msg: any): Promise<unknown> {
    const sess = this.getOrCreateStdioSession(serverName, this.config.upstream[serverName]);
    const id = msg.id ?? 0;
    return new Promise((resolve, reject) => {
      sess.pending.set(id, { resolve, reject });
      try {
        sess.proc.stdin!.write(JSON.stringify(msg) + "\n");
      } catch (e) {
        sess.pending.delete(id);
        reject(e as Error);
      }
      setTimeout(() => {
        if (sess.pending.has(id)) {
          sess.pending.delete(id);
          reject(new Error("Upstream stdio timeout (30s)"));
        }
      }, 30000);
    });
  }

  private getOrCreateStdioSession(serverName: string, upstream: UpstreamConfig): StdioSession {
    let sess = this.stdioSessions.get(serverName);
    if (sess && !sess.proc.killed) return sess;

    if (upstream.kind !== "stdio") {
      // shouldn't get here but be safe
      throw new Error("Cannot create stdio session for non-stdio upstream");
    }

    const proc = spawn(upstream.command, upstream.args, {
      env: { ...process.env, ...(upstream.env ?? {}) },
      stdio: ["pipe", "pipe", "pipe"],
    });

    sess = {
      proc,
      pending: new Map(),
      buffer: "",
      serverName,
      tools: [],
      lastScanAt: 0,
    };
    this.stdioSessions.set(serverName, sess);

    proc.stdout!.on("data", (chunk: Buffer) => {
      sess!.buffer += chunk.toString("utf8");
      // JSON-RPC over stdio uses newline-delimited JSON
      let nl: number;
      while ((nl = sess!.buffer.indexOf("\n")) >= 0) {
        const line = sess!.buffer.slice(0, nl).trim();
        sess!.buffer = sess!.buffer.slice(nl + 1);
        if (!line) continue;
        try {
          const parsed = JSON.parse(line);
          const id = parsed.id;
          if (id !== undefined && sess!.pending.has(id)) {
            const { resolve, reject } = sess!.pending.get(id)!;
            sess!.pending.delete(id);
            if (parsed.error) reject(new Error(parsed.error.message ?? "Upstream error"));
            else resolve(parsed.result);
          } else if (parsed.method === "notifications/message" || parsed.method === "notifications/progress") {
            // upstream-initiated notification — could forward via SSE in the future
            this.emit("notification", { server: serverName, ...parsed });
          }
        } catch {
          // malformed line — ignore
        }
      }
    });

    proc.stderr!.on("data", (chunk: Buffer) => {
      this.emit("stderr", { server: serverName, text: chunk.toString("utf8") });
    });

    proc.on("exit", (code) => {
      this.emit("upstream-exit", { server: serverName, code });
      // reject any pending
      for (const [, p] of sess!.pending) {
        p.reject(new Error(`Upstream exited with code ${code}`));
      }
      sess!.pending.clear();
      this.stdioSessions.delete(serverName);
    });

    return sess;
  }

  // ============================================================
  // STATIC + LLM ANALYSIS ON LIVE TOOLS
  // ============================================================
  private async scanServer(sess: StdioSession) {
    if (sess.tools.length === 0) return;
    const server: NormalizedServer = {
      name: sess.serverName,
      transport: "stdio",
      tools: sess.tools.map((t) => ({
        name: t.name ?? "",
        description: t.description ?? "",
        inputSchema: t.inputSchema ?? {},
        raw: t,
      })),
      sourceFormat: "live-tools-list",
      warnings: [],
      rawInput: sess.tools,
    };

    const staticRes = analyze([server], []);
    let llm: any = { enabled: false, used: false };
    if (this.config.llm.enabled) {
      const cfg = loadConfig();
      if (cfg) {
        llm = await analyzeWithLLM([server], cfg);
      }
    }

    const combined = combineResults(staticRes, llm);
    sess.analysis = {
      static: staticRes,
      llm,
      ...combined,
      durationMs: 0,
    };
    sess.lastScanAt = Date.now();
    this.emit("analysis", { server: sess.serverName, analysis: sess.analysis });
    this.persist();
  }

  // ============================================================
  // CALL EVALUATION (for enforce mode)
  // ============================================================
  private evaluateCall(serverName: string, toolName: string, _args: any): { allowed: boolean; reasons: string[]; findingIds: string[] } {
    const reasons: string[] = [];
    const findingIds: string[] = [];

    // Always allowed
    if (this.config.allowList.includes(toolName)) return { allowed: true, reasons: [], findingIds: [] };
    // Always-blocked method names
    if (this.config.mode !== "enforce") return { allowed: true, reasons: [], findingIds: [] };

    const sess = this.stdioSessions.get(serverName);
    if (!sess?.analysis) return { allowed: true, reasons: ["No analysis available yet"], findingIds: [] };

    const matching = sess.analysis.static.findings.filter((f) => f.target.endsWith(`.${toolName}`));
    for (const f of matching) {
      if (this.config.blockOnSeverity.includes(f.severity as any)) {
        reasons.push(`${f.rule}: ${f.message}`);
        findingIds.push(f.id);
      }
    }

    // Compose-chain heuristic: if previous call was a "read" tool, this is a "send/egress" tool
    const last = [...this.callLog].reverse().find((c) => c.server === serverName && c.method === "tools/call");
    if (last?.tool && /^(read|get|fetch|list|search|load)/i.test(last.tool) && /^(send|post|email|upload|publish|webhook)/i.test(toolName)) {
      reasons.push(`Composition risk: read-tool "${last.tool}" followed by egress-tool "${toolName}"`);
    }

    return { allowed: reasons.length === 0, reasons, findingIds };
  }

  // ============================================================
  // LOGGING
  // ============================================================
  private log(call: CallLog) {
    this.callLog.push(call);
    if (this.callLog.length > 1000) this.callLog.shift();
    this.emit("call", call);
    this.persist();
  }

  private persist() {
    if (!this.config.persist.path) return;
    try {
      const payload = {
        savedAt: Date.now(),
        sessions: [...this.stdioSessions.entries()].map(([name, s]) => ({
          name,
          tools: s.tools,
          analysis: s.analysis,
          lastScanAt: s.lastScanAt,
        })),
        calls: this.callLog,
      };
      writeFileSync(this.config.persist.path, JSON.stringify(payload, null, 2));
    } catch {
      // best effort
    }
  }

  // ============================================================
  // SERVER LIFECYCLE
  // ============================================================
  listen(): Promise<{ port: number }> {
    return new Promise((resolve) => {
      const server = this.app.listen(this.config.port, () => {
        const addr = server.address();
        const port = typeof addr === "object" && addr ? addr.port : this.config.port;
        console.log(`\n🛡️  MCPShield Proxy listening on http://localhost:${port}`);
        console.log(`   Mode: ${this.config.mode}`);
        console.log(`   Servers: ${Object.keys(this.config.upstream).join(", ")}`);
        console.log(`   Dashboard: http://localhost:${port}/dashboard\n`);
        resolve({ port });
      });
    });
  }

  async close() {
    for (const sess of this.stdioSessions.values()) {
      try { sess.proc.kill("SIGTERM"); } catch {}
    }
    this.persist();
  }

  // ============================================================
  // DASHBOARD HTML (no external deps, single file)
  // ============================================================
  private renderDashboard(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCPShield Proxy · Dashboard</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:0;background:#020617;color:#e2e8f0;padding:24px}
  h1{font-size:24px;margin:0 0 4px}
  .meta{color:#94a3b8;font-size:13px;margin-bottom:24px}
  .grid{display:grid;gap:16px}
  .card{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:16px}
  .grade{font-size:48px;font-weight:800;text-align:center;padding:8px;border-radius:12px;border:2px solid;width:80px;height:80px;display:flex;align-items:center;justify-content:center}
  .gA{color:#34d399;border-color:#34d399;background:#34d39910}
  .gB{color:#a3e635;border-color:#a3e635;background:#a3e63510}
  .gC{color:#fbbf24;border-color:#fbbf24;background:#fbbf2410}
  .gD{color:#fb923c;border-color:#fb923c;background:#fb923c10}
  .gF{color:#fb7185;border-color:#fb7185;background:#fb718510}
  .sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;margin-right:4px}
  .sev.critical{background:#fb718515;color:#fda4af;border:1px solid #fb718550}
  .sev.high{background:#fb923c15;color:#fdba74;border:1px solid #fb923c50}
  .sev.medium{background:#fbbf2415;color:#fcd34d;border:1px solid #fbbf2450}
  .sev.low{background:#38bdf815;color:#7dd3fc;border:1px solid #38bdf850}
  .sev.info{background:#94a3b815;color:#cbd5e1;border:1px solid #94a3b850}
  .tool{font-family:monospace;font-size:12px;color:#67e8f9}
  .finding{padding:8px 0;border-top:1px solid #1e293b}
  .finding:first-of-type{border-top:0}
  .muted{color:#64748b;font-size:12px}
  code{background:#1e293b;padding:1px 6px;border-radius:3px;font-size:12px}
  .row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  pre{background:#020617;border:1px solid #1e293b;border-radius:6px;padding:8px;font-size:11px;overflow-x:auto;margin:4px 0}
  .pill{display:inline-block;padding:2px 8px;background:#1e293b;border-radius:99px;font-size:11px;margin-right:4px}
  .ok{color:#34d399}
  .err{color:#fb7185}
</style>
</head>
<body>
<h1>🛡️ MCPShield Proxy</h1>
<div class="meta">
  Mode: <code>${this.config.mode}</code> ·
  Upstream servers: ${Object.keys(this.config.upstream).join(", ")} ·
  Auto-refreshes every 5s
</div>
<div id="content">Loading…</div>
<script>
async function refresh() {
  try {
    const [findings, log] = await Promise.all([
      fetch('/api/findings').then(r => r.json()),
      fetch('/api/log').then(r => r.json()),
    ]);

    let html = '<div class="grid">';

    // Per-server cards
    for (const s of findings.servers) {
      const a = s.analysis;
      const grade = a ? a.combinedGrade : '?';
      const score = a ? a.combinedScore : 0;
      const counts = a ? a.static.counts : {critical:0,high:0,medium:0,low:0,info:0};
      const findings = a ? a.static.findings : [];

      html += '<div class="card">';
      html += '<div class="row">';
      html += '<div class="grade g' + grade + '">' + grade + '</div>';
      html += '<div style="flex:1;min-width:0">';
      html += '<div style="font-size:18px;font-weight:700">' + s.server + '</div>';
      html += '<div class="muted">' + s.tools + ' tool(s) · score ' + score + '/100' + (a && a.llm.used ? ' · LLM-augmented' : '') + '</div>';
      html += '<div style="margin-top:6px">';
      html += '<span class="sev critical">' + counts.critical + ' critical</span>';
      html += '<span class="sev high">' + counts.high + ' high</span>';
      html += '<span class="sev medium">' + counts.medium + ' medium</span>';
      html += '<span class="sev low">' + counts.low + ' low</span>';
      html += '<span class="sev info">' + counts.info + ' info</span>';
      html += '</div></div>';
      html += '<div><button class="pill" onclick="rescan(\\''+s.server+'\\')">↻ rescan</button></div>';
      html += '</div>';

      if (findings.length > 0) {
        html += '<div style="margin-top:12px">';
        for (const f of findings.slice(0, 8)) {
          html += '<div class="finding">';
          html += '<span class="sev ' + f.severity + '">' + f.severity + '</span>';
          html += '<span class="tool">' + f.tv + '</span> · ';
          html += '<strong>' + f.rule + '</strong>';
          html += '<div class="muted" style="margin-top:2px">' + f.message + '</div>';
          if (f.evidence) html += '<pre>' + escapeHtml(f.evidence) + '</pre>';
          html += '</div>';
        }
        if (findings.length > 8) html += '<div class="muted">… and ' + (findings.length - 8) + ' more</div>';
        html += '</div>';
      }
      html += '</div>';
    }

    if (findings.servers.length === 0) {
      html += '<div class="card muted">No upstream servers have been contacted yet. Trigger a tools/list call from your MCP client.</div>';
    }

    // Recent call log
    html += '<div class="card"><strong>Recent calls</strong> (' + log.calls.length + ' total)';
    if (log.calls.length === 0) {
      html += '<div class="muted">No calls yet.</div>';
    } else {
      html += '<div style="margin-top:8px">';
      for (const c of log.calls.slice(-15).reverse()) {
        const cls = c.decision === 'allowed' ? 'ok' : c.decision === 'blocked' ? 'err' : '';
        html += '<div class="finding">';
        html += '<span class="pill ' + cls + '">' + c.decision + '</span>';
        html += '<span class="tool">' + c.method + '</span>';
        if (c.tool) html += ' · <code>' + c.tool + '</code>';
        html += ' · <span class="muted">' + new Date(c.timestamp).toLocaleTimeString() + ' · ' + c.durationMs + 'ms</span>';
        if (c.reasons.length > 0) html += '<div class="muted" style="margin-top:2px">' + c.reasons.join('; ') + '</div>';
        html += '</div>';
      }
      html += '</div>';
    }
    html += '</div>';

    html += '</div>';
    document.getElementById('content').innerHTML = html;
  } catch (e) {
    document.getElementById('content').innerHTML = '<div class="card err">Error: ' + e.message + '</div>';
  }
}
async function rescan(name) {
  await fetch('/api/rescan/' + encodeURIComponent(name), { method: 'POST' });
  setTimeout(refresh, 500);
}
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => c==='&'?'&amp;':c==='<'?'&lt;':c==='>'?'&gt;':c==='"'?'&quot;':'&#39;'); }
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`;
  }
}

// ============================================================
// CONFIG LOADER
// ============================================================
export function loadProxyConfig(path: string): ProxyConfig {
  if (!existsSync(path)) {
    throw new Error(`Config file not found: ${path}`);
  }
  const raw = readFileSync(path, "utf8");
  const parsed = parseConfig(raw);
  if (!parsed.ok) throw new Error(`Invalid config: ${parsed.error.message}`);
  const upstream: Record<string, UpstreamConfig> = {};
  for (const srv of parsed.servers) {
    if (srv.command) {
      upstream[srv.name] = { kind: "stdio", command: srv.command, args: srv.args ?? [], env: srv.env };
    } else if (srv.url) {
      upstream[srv.name] = { kind: "http", url: srv.url };
    }
  }
  return {
    port: Number(process.env.MCPSHIELD_PORT ?? 7777),
    upstream,
    mode: (process.env.MCPSHIELD_MODE as "monitor" | "enforce") ?? "monitor",
    llm: { enabled: process.env.GROQ_API_KEY ? true : false, model: process.env.GROQ_MODEL },
    blockOnSeverity: ["critical", "high"],
    scanOnList: true,
    blockOnCall: process.env.MCPSHIELD_MODE === "enforce",
    allowList: [],
    persist: { path: process.env.MCPSHIELD_DB ?? join(process.cwd(), "mcpshield-state.json") },
  };
}
