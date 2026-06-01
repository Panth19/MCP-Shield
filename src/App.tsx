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
  Component: ComponentType<{ onNavigate?: (id: string) => void }>;
}

const TABS: Tab[] = [
  {
    id: "scanner",
    layer: "L-RPE",
    name: "Tool Poisoning Scanner",
    shortName: "Scanner",
    icon: "🔍",
    blurb:
      "Static analysis of MCP tool definitions. Detects hidden instructions, data-exfiltration intent, consent bypass, and tool shadowing.",
    defends: "TC1 Tool Poisoning · TC6 Context Manipulation",
    Component: ScannerTool,
  },
  {
    id: "attestation",
    layer: "L-CTA",
    name: "Tool Attestation",
    shortName: "Attestation",
    icon: "📜",
    blurb:
      "Cryptographically sign tool definitions (SHA-256) at approval time and detect post-approval mutation, rollbacks, and swapped servers.",
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
      "Define capabilities and composition policies, then test whether a tool invocation (or a chain of them) is authorized.",
    defends: "TC4 Privilege Escalation · capability chaining",
    Component: AccessControlTool,
  },
  {
    id: "flow",
    layer: "L-IFT",
    name: "Information Flow",
    shortName: "Flow",
    icon: "🌊",
    blurb:
      "Label data by trust level and verify it cannot leak from a high-clearance server to a lower one — enforcing data confinement.",
    defends: "TC3 Cross-Server Data Leakage",
    Component: InfoFlowTool,
  },
];

export default function App() {
  const [active, setActive] = useState<TabId>("scanner");
  const tab = TABS.find((t) => t.id === active)!;
  const ActiveComponent = tab.Component;

  const navigate = (id: string) => {
    const valid = TABS.find((t) => t.id === id);
    if (valid) {
      setActive(valid.id);
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 antialiased selection:bg-cyan-400/30">
      {/* Header */}
      <header className="sticky top-0 z-40 border-b border-white/10 bg-slate-950/85 backdrop-blur-xl">
        <div className="mx-auto max-w-6xl px-4 py-3 sm:px-8">
          <div className="flex items-center justify-between gap-4">
            <button onClick={() => navigate("scanner")} className="flex items-center gap-2.5">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-400 to-indigo-500 text-lg shadow-lg shadow-indigo-500/30">
                🛡️
              </span>
              <div className="text-left">
                <div className="text-sm font-bold leading-tight text-white">
                  MCP<span className="text-cyan-400">Shield</span> Toolkit
                </div>
                <div className="hidden text-[11px] text-slate-500 sm:block">Free MCP security tools — 100% in your browser</div>
              </div>
            </button>
            <a
              href="https://modelcontextprotocol.io"
              target="_blank"
              rel="noreferrer"
              className="hidden rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:bg-white/10 sm:block"
            >
              About MCP ↗
            </a>
          </div>
        </div>
      </header>

      {/* Tabs */}
      <div className="mx-auto max-w-6xl px-4 sm:px-8">
        <div className="-mb-px flex gap-1 overflow-x-auto pt-3">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => navigate(t.id)}
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

      {/* Active tool */}
      <main className="border-t border-white/10 bg-slate-900/30" id="guide-content">
        <div className="mx-auto max-w-6xl px-4 py-8 sm:px-8">
          {/* tool header */}
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

          {/* render active component */}
          <ActiveComponent onNavigate={navigate} />
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-white/10 bg-slate-950 py-10">
        <div className="mx-auto max-w-6xl px-4 text-center text-xs text-slate-500 sm:px-8">
          <p>
            MCPShield Toolkit — a working implementation of the defense layers from "A Formal
            Security Framework for MCP-Based AI Agents."
          </p>
          <p className="mt-2">
            100% client-side · Web Crypto API · no servers, no API keys, no cost.
          </p>
        </div>
      </footer>
    </div>
  );
}
