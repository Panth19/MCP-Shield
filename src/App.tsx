import { useState, type ComponentType } from "react";
import { ScannerTool } from "./tools/ScannerTool";
import { AttestationTool } from "./tools/AttestationTool";
import { AccessControlTool } from "./tools/AccessControlTool";
import { InfoFlowTool } from "./tools/InfoFlowTool";
import { cn } from "./utils/cn";

type TabId = "scanner" | "attestation" | "access" | "flow";

interface Tab {
  id: TabId;
  layer: string;
  name: string;
  shortName: string;
  icon: string;
  blurb: string;
  defends: string;
  Component: ComponentType;
}

const TABS: Tab[] = [
  {
    id: "scanner",
    layer: "L-RPE + LLM",
    name: "MCP Security Analyzer",
    shortName: "Analyzer",
    icon: "🛡️",
    blurb:
      "Dual-mode analysis: pattern matching (50+ regex rules) catches known attack signatures, while LLM semantic analysis (via Groq free tier) reasons about novel attacks. Paste or upload any MCP config — Claude Desktop, Cursor, JSON-RPC tools/list, direct definitions.",
    defends: "TC1 Tool Poisoning · TC2 Rug Pull · TC6 Context Manipulation · + novel attacks via LLM",
    Component: ScannerTool,
  },
  {
    id: "attestation",
    layer: "L-CTA",
    name: "Tool Attestation",
    shortName: "Attestation",
    icon: "📜",
    blurb:
      "Cryptographically fingerprint tool definitions (SHA-256 via Web Crypto) at approval time. Detect post-approval mutation, version rollbacks, and swapped servers.",
    defends: "TC2 Rug Pull & Mutation · TC5 Server Trust",
    Component: AttestationTool,
  },
  {
    id: "access",
    layer: "L-CAC",
    name: "Access Control",
    shortName: "Access",
    icon: "🔑",
    blurb:
      "Define capabilities and composition policies. Test whether a tool invocation — or a chain of them — is authorized. Default-deny zero trust.",
    defends: "TC4 Privilege Escalation · capability chaining (TV12)",
    Component: AccessControlTool,
  },
  {
    id: "flow",
    layer: "L-IFT",
    name: "Information Flow",
    shortName: "Flow",
    icon: "🌊",
    blurb:
      "Label data by trust level. Enforce data confinement — verify information cannot leak from a high-clearance server to a lower one unless explicitly declassified.",
    defends: "TC3 Cross-Server Data Leakage",
    Component: InfoFlowTool,
  },
];

export default function App() {
  const [active, setActive] = useState<TabId>("scanner");
  const tab = TABS.find((t) => t.id === active)!;
  const ActiveComponent = tab.Component;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 antialiased selection:bg-cyan-400/30">
      {/* Header */}
      <header className="sticky top-0 z-40 border-b border-white/10 bg-slate-950/85 backdrop-blur-xl">
        <div className="mx-auto max-w-6xl px-4 py-3 sm:px-8">
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-2.5">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-400 to-indigo-500 text-lg shadow-lg shadow-indigo-500/30">
                🛡️
              </span>
              <div className="text-left">
                <div className="text-sm font-bold leading-tight text-white">
                  MCP<span className="text-cyan-400">Shield</span>
                </div>
                <div className="hidden text-[11px] text-slate-500 sm:block">
                  Real MCP security analyzer · LLM-powered · 100% client-side
                </div>
              </div>
            </div>
            <div className="hidden items-center gap-2 sm:flex">
              <a
                href="https://console.groq.com/keys"
                target="_blank"
                rel="noreferrer"
                className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-white/10"
              >
                Get Groq API key ↗
              </a>
              <a
                href="https://modelcontextprotocol.io"
                target="_blank"
                rel="noreferrer"
                className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-white/10"
              >
                About MCP ↗
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Tabs */}
      <div className="mx-auto max-w-6xl px-4 sm:px-8">
        <div className="-mb-px flex gap-1 overflow-x-auto pt-3">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setActive(t.id)}
              className={cn(
                "flex shrink-0 items-center gap-1.5 rounded-t-xl border-x border-t px-3 py-2.5 text-sm font-medium transition sm:px-4",
                active === t.id
                  ? "border-white/10 bg-slate-900/60 text-white"
                  : "border-transparent text-slate-500 hover:text-white"
              )}
            >
              <span className="text-base">{t.icon}</span>
              <span className="hidden sm:inline">{t.shortName}</span>
              <span
                className={cn(
                  "rounded px-1.5 py-0.5 font-mono text-[10px]",
                  active === t.id
                    ? "bg-cyan-400/10 text-cyan-300"
                    : "bg-white/5 text-slate-500"
                )}
              >
                {t.layer}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Active Tool */}
      <main className="border-t border-white/10 bg-slate-900/30">
        <div className="mx-auto max-w-6xl px-4 py-6 sm:px-8">
          <div className="mb-6 rounded-2xl border border-white/10 bg-slate-900/50 p-4 sm:p-5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xl">{tab.icon}</span>
              <h2 className="text-lg font-bold text-white">{tab.name}</h2>
              <span className="rounded-md border border-cyan-400/30 bg-cyan-400/10 px-2 py-0.5 font-mono text-[11px] text-cyan-300">
                {tab.layer}
              </span>
            </div>
            <p className="mt-2 text-sm text-slate-400">{tab.blurb}</p>
            <p className="mt-1.5 text-xs font-medium text-emerald-300">
              Defends: {tab.defends}
            </p>
          </div>

          <ActiveComponent />
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/10 bg-slate-950 py-8">
        <div className="mx-auto max-w-6xl px-4 text-center text-xs text-slate-500 sm:px-8">
          <p className="text-slate-400">
            MCPShield — Real MCP security analysis. Pattern matching + LLM reasoning.
          </p>
          <p className="mt-1">
            100% client-side · Web Crypto API · Groq free tier · No servers, no cost.
          </p>
          <p className="mt-3 text-[11px] text-slate-600">
            Implements the MCPShield defense-in-depth architecture from{" "}
            <em>"A Formal Security Framework for MCP-Based AI Agents"</em> (Acharya & Gupta, 2026).
          </p>
        </div>
      </footer>
    </div>
  );
}
