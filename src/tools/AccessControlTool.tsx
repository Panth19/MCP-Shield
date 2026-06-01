import { useState } from "react";
import { evaluateInvocation } from "../engine/accessControl";
import type { AccessDecision, Capability, CompositionRule, Scope } from "../engine/types";
import { Badge, Button, Card, Field, inputCls } from "../components/ui";
import { cn } from "../utils/cn";

const SCOPES: Scope[] = ["read", "write", "execute"];

const DEFAULT_CAPS: Capability[] = [
  { id: "cap-1", tool: "read_file", scope: "read", allowedParams: ["path"], issuedAt: Date.now() },
  { id: "cap-2", tool: "send_email", scope: "write", issuedAt: Date.now() },
];

const DEFAULT_RULES: CompositionRule[] = [
  {
    from: "read_file",
    to: "send_email",
    action: "deny",
    reason: "Reading a file then emailing it is a data-exfiltration chain (TV12).",
  },
];

export function AccessControlTool(_props: { onNavigate?: (id: string) => void }) {
  const [caps, setCaps] = useState<Capability[]>(DEFAULT_CAPS);
  const [rules, setRules] = useState<CompositionRule[]>(DEFAULT_RULES);

  const [tool, setTool] = useState("send_email");
  const [scope, setScope] = useState<Scope>("write");
  const [args, setArgs] = useState("to,body");
  const [prev, setPrev] = useState("read_file");
  const [decision, setDecision] = useState<AccessDecision | null>(null);

  // capability editor inputs
  const [ncTool, setNcTool] = useState("");
  const [ncScope, setNcScope] = useState<Scope>("read");
  const [ncParams, setNcParams] = useState("");

  const evaluate = () => {
    setDecision(
      evaluateInvocation(
        {
          tool: tool.trim(),
          scope,
          args: args.split(",").map((a) => a.trim()).filter(Boolean),
          previousTool: prev.trim() || undefined,
        },
        caps,
        rules
      )
    );
  };

  const addCap = () => {
    if (!ncTool.trim()) return;
    setCaps([
      ...caps,
      {
        id: `cap-${caps.length + 1}-${Date.now() % 1000}`,
        tool: ncTool.trim(),
        scope: ncScope,
        allowedParams: ncParams.split(",").map((p) => p.trim()).filter(Boolean),
        issuedAt: Date.now(),
      },
    ]);
    setNcTool("");
    setNcParams("");
  };

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      {/* Policy column */}
      <div className="space-y-6">
        <Card>
          <h3 className="text-sm font-semibold text-white">Capabilities (grants)</h3>
          <p className="mt-1 text-xs text-slate-400">
            Least privilege: an agent may only invoke a tool it holds a capability for. Everything else is denied.
          </p>
          <div className="mt-3 space-y-2">
            {caps.map((c) => (
              <div key={c.id} className="flex items-center gap-2 rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2 text-xs">
                <span className="font-mono text-cyan-300">{c.tool}</span>
                <Badge className="border-indigo-400/30 bg-indigo-500/15 text-indigo-200">{c.scope}</Badge>
                {c.allowedParams && c.allowedParams.length > 0 && (
                  <span className="text-slate-500">params: {c.allowedParams.join(", ")}</span>
                )}
                <button
                  onClick={() => setCaps(caps.filter((x) => x.id !== c.id))}
                  className="ml-auto text-slate-500 hover:text-rose-300"
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
          <div className="mt-3 grid grid-cols-[1fr_auto] gap-2">
            <input className={inputCls} placeholder="tool name (or *)" value={ncTool} onChange={(e) => setNcTool(e.target.value)} />
            <select className={inputCls} value={ncScope} onChange={(e) => setNcScope(e.target.value as Scope)}>
              {SCOPES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <input className={cn(inputCls, "col-span-2")} placeholder="allowed params (comma separated, optional)" value={ncParams} onChange={(e) => setNcParams(e.target.value)} />
          </div>
          <Button variant="ghost" className="mt-2" onClick={addCap}>+ Add capability</Button>
        </Card>

        <Card>
          <h3 className="text-sm font-semibold text-white">Composition rules</h3>
          <p className="mt-1 text-xs text-slate-400">
            Restrict which tools may run in sequence to block capability chaining (TV12).
          </p>
          <div className="mt-3 space-y-2">
            {rules.map((r, i) => (
              <div key={i} className="flex items-center gap-2 rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2 text-xs">
                <span className="font-mono text-cyan-300">{r.from}</span>
                <span className="text-slate-500">→</span>
                <span className="font-mono text-cyan-300">{r.to}</span>
                <Badge className={r.action === "deny" ? "border-rose-400/30 bg-rose-500/15 text-rose-200" : "border-amber-400/30 bg-amber-500/15 text-amber-200"}>{r.action}</Badge>
                <button onClick={() => setRules(rules.filter((_, x) => x !== i))} className="ml-auto text-slate-500 hover:text-rose-300">✕</button>
              </div>
            ))}
            {rules.length === 0 && <p className="text-xs text-slate-600">No composition rules.</p>}
          </div>
        </Card>
      </div>

      {/* Tester column */}
      <div className="space-y-6">
        <Card>
          <h3 className="text-sm font-semibold text-white">Test a tool invocation</h3>
          <div className="mt-3 grid grid-cols-2 gap-3">
            <Field label="Tool">
              <input className={inputCls} value={tool} onChange={(e) => setTool(e.target.value)} />
            </Field>
            <Field label="Scope">
              <select className={inputCls} value={scope} onChange={(e) => setScope(e.target.value as Scope)}>
                {SCOPES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
            <Field label="Args (comma separated)">
              <input className={inputCls} value={args} onChange={(e) => setArgs(e.target.value)} />
            </Field>
            <Field label="Previous tool (chain)" hint="optional — for composition checks">
              <input className={inputCls} value={prev} onChange={(e) => setPrev(e.target.value)} />
            </Field>
          </div>
          <Button className="mt-3" onClick={evaluate}>⚖ Evaluate</Button>
        </Card>

        {decision && (
          <Card className={cn("border-2", decision.allowed ? "border-emerald-400/40" : "border-rose-400/40")}>
            <div className="flex items-center gap-2">
              <span className="text-2xl">{decision.allowed ? "✅" : "⛔"}</span>
              <span className={cn("text-lg font-bold", decision.allowed ? "text-emerald-300" : "text-rose-300")}>
                {decision.allowed ? "ALLOWED" : "DENIED"}
              </span>
            </div>
            <div className="mt-3 space-y-1.5">
              {decision.reasons.map((r, i) => (
                <div key={i} className="flex gap-2 text-sm text-slate-300">
                  <span className="text-slate-500">•</span> {r}
                </div>
              ))}
            </div>
            {decision.warnings.length > 0 && (
              <div className="mt-3 space-y-1.5 border-t border-white/5 pt-3">
                {decision.warnings.map((w, i) => (
                  <div key={i} className="flex gap-2 text-sm text-amber-200">
                    <span>⚠</span> {w}
                  </div>
                ))}
              </div>
            )}
          </Card>
        )}
      </div>
    </div>
  );
}
