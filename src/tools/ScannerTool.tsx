import { useCallback, useEffect, useMemo, useState } from "react";
import { scanServer } from "../engine/scanner";
import { parseConfig, probeMCPEndpoint } from "../engine/configParser";
import {
  addScanHistory,
  clearScanHistory,
  exportAsCsv,
  exportAsJson,
  getScanHistory,
  type ScanHistoryEntry,
} from "../engine/storage";
import type { MCPServer, ScanResult, Severity } from "../engine/types";
import { SAMPLE_SERVERS, SAMPLE_CONFIGS } from "../engine/samples";
import { Badge, Button, Card, inputCls, severityStyle } from "../components/ui";
import { cn } from "../utils/cn";

const gradeColor: Record<ScanResult["grade"], string> = {
  A: "text-emerald-300 border-emerald-400/40 bg-emerald-400/10",
  B: "text-lime-300 border-lime-400/40 bg-lime-400/10",
  C: "text-amber-300 border-amber-400/40 bg-amber-400/10",
  D: "text-orange-300 border-orange-400/40 bg-orange-400/10",
  F: "text-rose-300 border-rose-400/40 bg-rose-400/10",
};
const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export function ScannerTool(_props: { onNavigate?: (id: string) => void }) {
  const [text, setText] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [format, setFormat] = useState("");
  const [serverName, setServerName] = useState("");
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [probeUrl, setProbeUrl] = useState("");
  const [probing, setProbing] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [parseWarnings, setParseWarnings] = useState<string[]>([]);

  useEffect(() => { setHistory(getScanHistory()); }, []);

  const runScan = useCallback((raw?: string) => {
    const src = raw ?? text;
    setError(null);
    setResult(null);
    setFormat("");
    setParseWarnings([]);

    // Use the real config parser
    let parsed: ReturnType<typeof parseConfig>;
    try {
      parsed = parseConfig(src);
    } catch (e) {
      setError((e as Error).message);
      return;
    }

    setFormat(parsed.format);
    setParseWarnings(parsed.warnings);

    if (parsed.servers.length === 0) {
      setError("No MCP servers found in the input.");
      return;
    }

    // Merge all servers' tools into one scan
    const merged: MCPServer = {
      name: parsed.servers.map((s) => s.name).join(", "),
      tools: parsed.servers.flatMap((s) => s.tools),
    };

    setServerName(merged.name);
    const scanResult = scanServer(merged);
    setResult(scanResult);

    // Save to history
    const entry: ScanHistoryEntry = {
      id: `scan-${Date.now()}`,
      serverName: merged.name,
      timestamp: Date.now(),
      grade: scanResult.grade,
      score: scanResult.score,
      findingCount: scanResult.findings.length,
      toolCount: scanResult.toolCount,
      inputJson: src.slice(0, 2000),
    };
    addScanHistory(entry);
    setHistory(getScanHistory());
  }, [text]);

  const loadSample = (key: string) => {
    const sample = SAMPLE_SERVERS[key];
    const json = JSON.stringify(sample, null, 2);
    setText(json);
    // runScan with that json
    setTimeout(() => runScan(json), 0);
  };

  const handleProbe = async () => {
    if (!probeUrl.trim()) return;
    setProbing(true);
    setError(null);
    try {
      const result = await probeMCPEndpoint(probeUrl);
      const json = JSON.stringify(
        { name: probeUrl, tools: result.servers.flatMap((s) => s.tools) },
        null, 2
      );
      setText(json);
      runScan(json);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setProbing(false);
    }
  };

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const content = reader.result as string;
      setText(content);
      runScan(content);
    };
    reader.readAsText(file);
  }, [runScan]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const content = reader.result as string;
      setText(content);
      runScan(content);
    };
    reader.readAsText(file);
  }, [runScan]);

  const filtered = useMemo(
    () => result ? result.findings.filter((f) => filter === "all" || f.severity === filter) : [],
    [result, filter]
  );

  const handleExportJson = () => {
    if (!result) return;
    exportAsJson({
      serverName,
      scannedAt: new Date(result.scannedAt).toISOString(),
      grade: result.grade,
      score: result.score,
      toolCount: result.toolCount,
      counts: result.counts,
      findings: result.findings,
    }, `mcpshield-scan-${serverName.replace(/[^a-z0-9]/gi, "-")}.json`);
  };

  const handleExportCsv = () => {
    if (!result) return;
    exportAsCsv(
      result.findings.map((f) => ({
        severity: f.severity,
        threatVector: f.tv,
        rule: f.rule,
        tool: f.toolName,
        field: f.field,
        evidence: f.evidence ?? "",
        recommendation: f.recommendation,
      })),
      `mcpshield-scan-${serverName.replace(/[^a-z0-9]/gi, "-")}.csv`
    );
  };

  return (
    <div className="space-y-6">
      {/* Input methods */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card
          className="relative"
        >
          <div
            className="absolute inset-0 rounded-2xl"
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleFileDrop}
          />
          <div className="relative">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-sm font-semibold text-white">Input — paste, upload, or probe</h3>
              <div className="flex flex-wrap gap-1.5">
                {Object.keys(SAMPLE_SERVERS).map((k) => (
                  <button key={k} onClick={() => loadSample(k)}
                    className={cn("rounded-lg border px-2.5 py-1 text-[11px] font-medium transition",
                      k.startsWith("Malicious")
                        ? "border-rose-400/30 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20"
                        : "border-emerald-400/30 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20"
                    )}>
                    {k.startsWith("Malicious") ? "☠ " : "✓ "}{k.split(":")[1].trim()}
                  </button>
                ))}
                {Object.entries(SAMPLE_CONFIGS).map(([label, raw]) => (
                  <button key={label} onClick={() => { setText(raw); runScan(raw); }}
                    className="rounded-lg border border-indigo-400/30 bg-indigo-500/10 px-2.5 py-1 text-[11px] font-medium text-indigo-200 transition hover:bg-indigo-500/20">
                    📄 {label}
                  </button>
                ))}
              </div>
            </div>

            {/* Supported formats hint */}
            <div className="mb-2 rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2 text-[11px] text-slate-500">
              <span className="font-semibold text-slate-400">Accepts:</span>{" "}
              claude_desktop_config.json · Cursor settings · JSON-RPC tools/list response · direct {"{"} tools:[...] {"}"} · bare tool arrays
            </div>

            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              spellCheck={false}
              placeholder={`Paste any MCP config here, or drag & drop a .json file.\n\nExamples:\n  • claude_desktop_config.json (from ~/.config/claude/)\n  • A tools/list JSON-RPC response\n  • A server definition: { "name": "...", "tools": [...] }`}
              className={cn(inputCls, "h-60 resize-none font-mono text-[12px] leading-relaxed")}
            />

            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Button onClick={() => runScan()} disabled={!text.trim()}>🔍 Scan</Button>
              <label className="cursor-pointer rounded-xl border border-white/15 bg-white/5 px-4 py-2 text-sm font-semibold text-white transition hover:bg-white/10">
                📁 Upload file
                <input type="file" accept=".json,.jsonc,.txt" className="hidden" onChange={handleFileSelect} />
              </label>
              <Button variant="ghost" onClick={() => { setText(""); setResult(null); setError(null); setFormat(""); setParseWarnings([]); }}>Clear</Button>
            </div>

            {/* Live probe */}
            <div className="mt-3 flex gap-2">
              <input
                className={cn(inputCls, "flex-1")}
                placeholder="http://localhost:3000 — probe a live MCP server"
                value={probeUrl}
                onChange={(e) => setProbeUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleProbe()}
              />
              <Button variant="ghost" onClick={handleProbe} disabled={probing || !probeUrl.trim()}>
                {probing ? "⏳" : "⚡"} Probe
              </Button>
            </div>

            {error && (
              <pre className="mt-3 whitespace-pre-wrap rounded-lg border border-rose-400/30 bg-rose-950/30 p-3 text-xs text-rose-200">
                {error}
              </pre>
            )}
            {parseWarnings.length > 0 && parseWarnings.map((w, i) => (
              <div key={i} className="mt-2 flex gap-2 rounded-lg border border-amber-400/20 bg-amber-500/5 p-2 text-xs text-amber-200">
                <span>⚠</span> {w}
              </div>
            ))}
          </div>
        </Card>

        {/* Report summary */}
        <Card>
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Security Report</h3>
            {result && (
              <div className="flex gap-1.5">
                <button onClick={handleExportJson} className="rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-300 hover:bg-white/10">⬇ JSON</button>
                <button onClick={handleExportCsv} className="rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-300 hover:bg-white/10">⬇ CSV</button>
              </div>
            )}
          </div>
          {!result ? (
            <div className="flex h-60 flex-col items-center justify-center text-center text-sm text-slate-500">
              <span className="mb-3 text-4xl">🛡️</span>
              <p>Paste a config, upload a file, or load a sample.</p>
              <p className="mt-1 text-xs text-slate-600">Works with real Claude Desktop / Cursor configs.</p>
            </div>
          ) : (
            <div>
              <div className="flex items-center gap-4">
                <div className={cn("flex h-20 w-20 shrink-0 flex-col items-center justify-center rounded-2xl border-2", gradeColor[result.grade])}>
                  <span className="text-3xl font-black">{result.grade}</span>
                </div>
                <div>
                  <div className="text-sm text-slate-400">
                    <span className="font-mono text-white">{serverName}</span>
                  </div>
                  <div className="text-2xl font-bold text-white">
                    Risk score {result.score}<span className="text-base font-normal text-slate-500">/100</span>
                  </div>
                  <div className="text-xs text-slate-500">
                    {result.findings.length} finding(s) across {result.toolCount} tool(s)
                    {format && <span className="ml-1 text-cyan-400">· {format}</span>}
                  </div>
                </div>
              </div>

              <div className="mt-4 grid grid-cols-5 gap-2">
                {severityOrder.map((s) => (
                  <button key={s} onClick={() => setFilter(filter === s ? "all" : s)}
                    className={cn("rounded-xl border p-2 text-center transition",
                      result.counts[s] > 0 ? severityStyle[s] : "border-white/5 bg-white/[0.02] text-slate-600",
                      filter === s && "ring-2 ring-white/40"
                    )}>
                    <div className="text-lg font-bold">{result.counts[s]}</div>
                    <div className="text-[9px] uppercase tracking-wide">{s}</div>
                  </button>
                ))}
              </div>
              {filter !== "all" && (
                <button onClick={() => setFilter("all")} className="mt-2 text-[11px] text-cyan-400 hover:underline">
                  ← Show all findings
                </button>
              )}
              {result.findings.length === 0 && (
                <div className="mt-4 rounded-xl border border-emerald-400/30 bg-emerald-500/10 p-4 text-sm text-emerald-200">
                  ✓ No poisoning signatures detected. This doesn't mean the server is safe —
                  attestation and access control provide additional layers.
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      {/* Findings list */}
      {result && filtered.length > 0 && (
        <div className="space-y-3">
          {filtered.map((f) => (
            <Card key={f.id} className="border-l-4 border-l-transparent">
              <div className="flex flex-wrap items-center gap-2">
                <Badge className={severityStyle[f.severity]}>{f.severity.toUpperCase()}</Badge>
                <Badge className="border-white/15 bg-white/5 font-mono text-cyan-300">{f.tv}</Badge>
                <span className="text-sm font-semibold text-white">{f.rule}</span>
                <span className="ml-auto rounded-md bg-white/5 px-2 py-0.5 font-mono text-[11px] text-slate-400">
                  {f.toolName} · {f.field}
                </span>
              </div>
              <p className="mt-2 text-sm text-slate-300">{f.message}</p>
              {f.evidence && (
                <pre className="mt-2 overflow-x-auto rounded-lg border border-rose-400/20 bg-rose-950/30 px-3 py-2 font-mono text-[12px] text-rose-200">
                  {f.evidence}
                </pre>
              )}
              <p className="mt-2 text-xs text-emerald-300">
                <span className="font-semibold">Fix: </span>{f.recommendation}
              </p>
            </Card>
          ))}
        </div>
      )}

      {/* Scan history */}
      <Card>
        <div className="flex items-center justify-between">
          <button onClick={() => setShowHistory(!showHistory)} className="flex items-center gap-2 text-sm font-semibold text-white">
            <span>{showHistory ? "▾" : "▸"}</span>
            Scan History ({history.length})
          </button>
          {history.length > 0 && (
            <div className="flex gap-1.5">
              <button onClick={() => exportAsJson(history, "mcpshield-scan-history.json")}
                className="rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-300 hover:bg-white/10">
                ⬇ Export
              </button>
              <button onClick={() => { clearScanHistory(); setHistory([]); }}
                className="rounded-lg border border-rose-400/20 bg-rose-500/5 px-2 py-1 text-[11px] text-rose-300 hover:bg-rose-500/10">
                🗑 Clear
              </button>
            </div>
          )}
        </div>
        {showHistory && (
          <div className="mt-3 space-y-1.5">
            {history.length === 0 && <p className="text-xs text-slate-600">No scans yet. Results are saved automatically.</p>}
            {history.map((h) => (
              <button
                key={h.id}
                onClick={() => { setText(h.inputJson); runScan(h.inputJson); }}
                className="flex w-full items-center gap-3 rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2 text-left text-xs transition hover:bg-white/[0.04]"
              >
                <span className={cn("flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border text-sm font-bold", gradeColor[h.grade])}>
                  {h.grade}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium text-white">{h.serverName}</div>
                  <div className="text-slate-500">
                    {h.findingCount} findings · {h.toolCount} tools · {new Date(h.timestamp).toLocaleString()}
                  </div>
                </div>
                <span className="text-slate-600">↻</span>
              </button>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
