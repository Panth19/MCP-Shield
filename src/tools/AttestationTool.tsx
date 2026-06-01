import { useEffect, useState } from "react";
import { attestServer, checkIntegrity } from "../engine/attestation";
import { parseConfig } from "../engine/configParser";
import {
  addBaseline,
  clearBaselines,
  exportAsJson,
  getBaselines,
  removeBaseline,
  type StoredBaseline,
} from "../engine/storage";
import type { IntegrityCheck, MCPServer } from "../engine/types";
import { Badge, Button, Card, inputCls } from "../components/ui";
import { cn } from "../utils/cn";

const statusStyle: Record<IntegrityCheck["status"], string> = {
  unchanged: "text-emerald-300 bg-emerald-500/15 border-emerald-400/30",
  mutated: "text-rose-300 bg-rose-500/15 border-rose-400/30",
  "rolled-back": "text-orange-300 bg-orange-500/15 border-orange-400/30",
  new: "text-amber-300 bg-amber-500/15 border-amber-400/30",
  removed: "text-slate-300 bg-white/5 border-white/15",
};

export function AttestationTool(_props: { onNavigate?: (id: string) => void }) {
  const [baselines, setBaselines] = useState<StoredBaseline[]>([]);
  const [activeBaseline, setActiveBaseline] = useState<StoredBaseline | null>(null);
  const [checks, setChecks] = useState<IntegrityCheck[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [approvedJson, setApprovedJson] = useState("");
  const [verifyJson, setVerifyJson] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const stored = getBaselines();
    setBaselines(stored);
    if (stored.length > 0 && !activeBaseline) {
      setActiveBaseline(stored[0]);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const createBaseline = async (json: string) => {
    setError(null);
    setBusy(true);
    setChecks(null);

    try {
      const parsed = parseConfig(json);
      if (parsed.servers.length === 0) throw new Error("No servers found.");

      const server = parsed.servers[0];
      const merged: MCPServer = {
        name: parsed.servers.map((s) => s.name).join(", "),
        version: server.version ?? "1.0.0",
        tools: parsed.servers.flatMap((s) => s.tools),
      };

      const attestations = await attestServer(merged);
      const bl: StoredBaseline = {
        id: `bl-${Date.now()}`,
        name: `${merged.name}@${merged.version}`,
        timestamp: Date.now(),
        attestations,
        sourceJson: json,
      };
      addBaseline(bl);
      setBaselines(getBaselines());
      setActiveBaseline(bl);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const verify = async (json: string) => {
    if (!activeBaseline) return;
    setError(null);
    setBusy(true);

    try {
      const parsed = parseConfig(json);
      if (parsed.servers.length === 0) throw new Error("No servers found.");

      const merged: MCPServer = {
        name: parsed.servers.map((s) => s.name).join(", "),
        version: parsed.servers[0].version ?? "1.0.0",
        tools: parsed.servers.flatMap((s) => s.tools),
      };

      const result = await checkIntegrity(activeBaseline.attestations, merged);
      setChecks(result);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const stats = checks
    ? {
        total: checks.length,
        unchanged: checks.filter((c) => c.status === "unchanged").length,
        mutated: checks.filter((c) => c.status === "mutated").length,
        rolled: checks.filter((c) => c.status === "rolled-back").length,
        added: checks.filter((c) => c.status === "new").length,
        removed: checks.filter((c) => c.status === "removed").length,
      }
    : null;

  return (
    <div className="space-y-6">
      {/* Step 1: Create baseline */}
      <Card>
        <h3 className="text-sm font-semibold text-white">Step 1 — Attest the approved version</h3>
        <p className="mt-1 text-xs text-slate-400">
          Paste your MCP server JSON (any supported format). Each tool definition gets a SHA-256 fingerprint that is stored in your browser's localStorage. This is your immutable baseline.
        </p>
        <textarea
          value={approvedJson}
          onChange={(e) => setApprovedJson(e.target.value)}
          spellCheck={false}
          placeholder='Paste your approved MCP server config here — same formats as the Scanner.'
          className={cn(inputCls, "mt-3 h-36 resize-none font-mono text-[12px] leading-relaxed")}
        />
        <div className="mt-2 flex gap-2">
          <Button onClick={() => createBaseline(approvedJson)} disabled={busy || !approvedJson.trim()}>
            📜 Create baseline
          </Button>
        </div>
      </Card>

      {/* Stored baselines */}
      <Card>
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-white">
            Stored baselines ({baselines.length})
          </h3>
          <div className="flex gap-1.5">
            {baselines.length > 0 && (
              <>
                <button onClick={() => exportAsJson(baselines, "mcpshield-baselines.json")}
                  className="rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-300 hover:bg-white/10">
                  ⬇ Export
                </button>
                <button onClick={() => { clearBaselines(); setBaselines([]); setActiveBaseline(null); }}
                  className="rounded-lg border border-rose-400/20 bg-rose-500/5 px-2 py-1 text-[11px] text-rose-300 hover:bg-rose-500/10">
                  🗑 Clear
                </button>
              </>
            )}
          </div>
        </div>
        <div className="mt-3 space-y-2">
          {baselines.length === 0 && (
            <p className="text-xs text-slate-600">No baselines yet. Create one above — it persists across page refreshes.</p>
          )}
          {baselines.map((bl) => (
            <div key={bl.id} className={cn(
              "flex items-center gap-3 rounded-lg border px-3 py-2 transition",
              activeBaseline?.id === bl.id
                ? "border-cyan-400/40 bg-cyan-400/5"
                : "border-white/5 bg-white/[0.02]"
            )}>
              <button
                onClick={() => setActiveBaseline(bl)}
                className="flex-1 text-left"
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-white">{bl.name}</span>
                  <span className="text-[10px] text-slate-500">{bl.attestations.length} tools</span>
                  {activeBaseline?.id === bl.id && (
                    <Badge className="border-cyan-400/30 bg-cyan-400/10 text-cyan-300">ACTIVE</Badge>
                  )}
                </div>
                <div className="mt-0.5 text-[10px] text-slate-500">{new Date(bl.timestamp).toLocaleString()}</div>
              </button>
              <button onClick={() => { removeBaseline(bl.id); setBaselines(getBaselines()); if (activeBaseline?.id === bl.id) setActiveBaseline(null); }}
                className="text-slate-600 hover:text-rose-300">✕</button>
            </div>
          ))}
        </div>

        {activeBaseline && (
          <div className="mt-3 space-y-1">
            <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Attestation records for {activeBaseline.name}
            </div>
            {activeBaseline.attestations.map((a) => (
              <div key={a.toolName} className="rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-white">{a.toolName}</span>
                  <span className="text-[10px] text-slate-500">v{a.version}</span>
                </div>
                <div className="mt-1 truncate font-mono text-[11px] text-cyan-300">SHA-256: {a.hash}</div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Step 2: Verify */}
      <Card>
        <h3 className="text-sm font-semibold text-white">Step 2 — Verify current version against baseline</h3>
        <p className="mt-1 text-xs text-slate-400">
          Paste the server's current config/tools. Every tool is re-hashed and compared to the active baseline.
          Detects mutations (TV5), rollbacks (TV6), added tools, and removed tools.
        </p>
        <textarea
          value={verifyJson}
          onChange={(e) => setVerifyJson(e.target.value)}
          spellCheck={false}
          placeholder='Paste the current server definition to compare against the baseline.'
          className={cn(inputCls, "mt-3 h-36 resize-none font-mono text-[12px] leading-relaxed")}
        />
        <div className="mt-2 flex gap-2">
          <Button onClick={() => verify(verifyJson)} disabled={busy || !verifyJson.trim() || !activeBaseline}>
            🔬 Verify integrity
          </Button>
          {!activeBaseline && <span className="self-center text-xs text-amber-300">← Create a baseline first</span>}
        </div>

        {error && <p className="mt-2 text-xs text-rose-300">{error}</p>}

        {checks && stats && (
          <div className="mt-4">
            <div className="mb-3 grid grid-cols-5 gap-2 text-center text-xs">
              <Stat n={stats.unchanged} label="Unchanged" color="text-emerald-300" />
              <Stat n={stats.mutated} label="Mutated" color="text-rose-300" />
              <Stat n={stats.rolled} label="Rolled back" color="text-orange-300" />
              <Stat n={stats.added} label="New" color="text-amber-300" />
              <Stat n={stats.removed} label="Removed" color="text-slate-300" />
            </div>
            <div className="space-y-2">
              {checks.map((c) => (
                <div key={c.toolName} className="rounded-xl border border-white/5 bg-white/[0.02] p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className={statusStyle[c.status]}>{c.status.toUpperCase()}</Badge>
                    <span className="font-mono text-sm text-white">{c.toolName}</span>
                    {c.oldVersion && (
                      <span className="text-[11px] text-slate-500">{c.oldVersion} → {c.newVersion ?? "—"}</span>
                    )}
                  </div>
                  <p className={cn("mt-1.5 text-xs", c.status === "unchanged" ? "text-slate-400" : "text-rose-200")}>
                    {c.detail}
                  </p>
                  {c.status !== "unchanged" && c.oldHash && c.newHash && (
                    <div className="mt-2 space-y-1 font-mono text-[10px]">
                      <div className="truncate text-slate-500">approved: {c.oldHash}</div>
                      <div className="truncate text-rose-300">current: {c.newHash}</div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

function Stat({ n, label, color }: { n: number; label: string; color: string }) {
  return (
    <div className="rounded-lg border border-white/5 bg-white/[0.02] p-2">
      <div className={cn("text-lg font-bold", n > 0 ? color : "text-slate-600")}>{n}</div>
      <div className="text-[9px] uppercase text-slate-500">{label}</div>
    </div>
  );
}
