import { useState } from "react";
import { checkFlow, LEVELS, type Datum, type FlowServer, type Level } from "../engine/infoFlow";
import { Badge, Button, Card, Field, inputCls } from "../components/ui";
import { cn } from "../utils/cn";

const levelColor: Record<Level, string> = {
  public: "border-emerald-400/30 bg-emerald-500/15 text-emerald-200",
  internal: "border-sky-400/30 bg-sky-500/15 text-sky-200",
  confidential: "border-amber-400/30 bg-amber-500/15 text-amber-200",
  restricted: "border-rose-400/30 bg-rose-500/15 text-rose-200",
};

const DEFAULT_DATA: Datum[] = [
  { id: "d1", label: "customer email", level: "confidential", origin: "crm-mcp" },
  { id: "d2", label: "public docs snippet", level: "public", origin: "docs-mcp" },
  { id: "d3", label: "API private key", level: "restricted", origin: "vault-mcp" },
];

export function InfoFlowTool(_props: { onNavigate?: (id: string) => void }) {
  const [data, setData] = useState<Datum[]>(DEFAULT_DATA);
  const [target, setTarget] = useState<FlowServer>({ name: "analytics-mcp", clearance: "internal" });
  const [declassified, setDeclassified] = useState<Set<string>>(new Set());

  const [ndLabel, setNdLabel] = useState("");
  const [ndLevel, setNdLevel] = useState<Level>("confidential");

  const checks = checkFlow(data, target, declassified);
  const blocked = checks.filter((c) => !c.allowed).length;

  const toggleDeclassify = (id: string) => {
    const next = new Set(declassified);
    next.has(id) ? next.delete(id) : next.add(id);
    setDeclassified(next);
  };

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="space-y-6">
        <Card>
          <h3 className="text-sm font-semibold text-white">Data in the agent context</h3>
          <p className="mt-1 text-xs text-slate-400">
            Each datum is tainted with the trust level of the server it came from.
          </p>
          <div className="mt-3 space-y-2">
            {data.map((d) => (
              <div key={d.id} className="flex items-center gap-2 rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2 text-xs">
                <span className="text-white">{d.label}</span>
                <Badge className={levelColor[d.level]}>{d.level}</Badge>
                <span className="text-slate-500">from {d.origin}</span>
                <button onClick={() => setData(data.filter((x) => x.id !== d.id))} className="ml-auto text-slate-500 hover:text-rose-300">✕</button>
              </div>
            ))}
          </div>
          <div className="mt-3 grid grid-cols-[1fr_auto_auto] gap-2">
            <input className={inputCls} placeholder="data label" value={ndLabel} onChange={(e) => setNdLabel(e.target.value)} />
            <select className={inputCls} value={ndLevel} onChange={(e) => setNdLevel(e.target.value as Level)}>
              {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}
            </select>
            <Button variant="ghost" onClick={() => {
              if (!ndLabel.trim()) return;
              setData([...data, { id: `d${Date.now()}`, label: ndLabel.trim(), level: ndLevel, origin: "manual" }]);
              setNdLabel("");
            }}>+ Add</Button>
          </div>
        </Card>

        <Card>
          <h3 className="text-sm font-semibold text-white">Target server</h3>
          <div className="mt-3 grid grid-cols-2 gap-3">
            <Field label="Server name">
              <input className={inputCls} value={target.name} onChange={(e) => setTarget({ ...target, name: e.target.value })} />
            </Field>
            <Field label="Clearance level" hint="max level it may receive">
              <select className={inputCls} value={target.clearance} onChange={(e) => setTarget({ ...target, clearance: e.target.value as Level })}>
                {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}
              </select>
            </Field>
          </div>
        </Card>
      </div>

      <Card>
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-white">Flow decision</h3>
          <Badge className={blocked > 0 ? "border-rose-400/30 bg-rose-500/15 text-rose-200" : "border-emerald-400/30 bg-emerald-500/15 text-emerald-200"}>
            {blocked > 0 ? `${blocked} blocked` : "all permitted"}
          </Badge>
        </div>
        <p className="mt-1 text-xs text-slate-400">
          Data confinement: <span className="font-mono">ℓ(d) ⊑ ℓ(target)</span>. Higher-level data may not flow to a lower-clearance server unless explicitly declassified.
        </p>
        <div className="mt-4 space-y-2">
          {checks.map((c) => (
            <div
              key={c.datum.id}
              className={cn(
                "rounded-xl border p-3",
                c.allowed
                  ? c.needsDeclassification
                    ? "border-amber-400/30 bg-amber-500/10"
                    : "border-emerald-400/20 bg-emerald-500/5"
                  : "border-rose-400/30 bg-rose-500/10"
              )}
            >
              <div className="flex items-center gap-2">
                <span>{c.allowed ? (c.needsDeclassification ? "⚠" : "✅") : "⛔"}</span>
                <span className="text-sm font-medium text-white">{c.datum.label}</span>
                <Badge className={levelColor[c.datum.level]}>{c.datum.level}</Badge>
              </div>
              <p className={cn("mt-1.5 text-xs", c.allowed ? "text-slate-300" : "text-rose-200")}>{c.message}</p>
              {!c.allowed && (
                <button
                  onClick={() => toggleDeclassify(c.datum.id)}
                  className="mt-2 rounded-md border border-amber-400/30 bg-amber-500/10 px-2 py-1 text-[11px] text-amber-200 hover:bg-amber-500/20"
                >
                  🔓 Explicitly declassify (authorize override)
                </button>
              )}
              {c.needsDeclassification && c.allowed && (
                <button
                  onClick={() => toggleDeclassify(c.datum.id)}
                  className="mt-2 rounded-md border border-white/15 bg-white/5 px-2 py-1 text-[11px] text-slate-300 hover:bg-white/10"
                >
                  ↩ Revoke declassification
                </button>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
