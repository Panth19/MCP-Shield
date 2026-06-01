import { useState, type ComponentType } from "react";
import { ScannerTool } from "./tools/ScannerTool";
import { AttestationTool } from "./tools/AttestationTool";
import { AccessControlTool } from "./tools/AccessControlTool";
import { InfoFlowTool } from "./tools/InfoFlowTool";
import { GuideTool } from "./tools/GuideTool";
import { cn } from "./utils/cn";

type TabId = "guide" | "scanner" | "attestation" | "access" | "flow";

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
    id: "guide",
    layer: "START",
    name: "Deploy & Test Guide",
    shortName: "Guide",
    icon: "📋",
    blurb:
      "Step-by-step instructions to deploy the toolkit for free, and a complete walkthrough to test every feature with expected results.",
    defends: "All 7 threat categories covered end-to-end",
    Component: GuideTool,
  },
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
  const [active, setActive] = useState<TabId>("guide");
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
            <button onClick={() => navigate("guide")} className="flex items-center gap-2.5">
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

      {/* Intro — only on guide tab */}
      {active === "guide" && (
        <section className="border-b border-white/5 bg-[radial-gradient(60%_60%_at_50%_0%,rgba(56,189,248,0.10),transparent)]">
          <div className="mx-auto max-w-6xl px-4 py-10 sm:px-8 sm:py-14">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/30 bg-cyan-400/10 px-3 py-1 text-[11px] font-medium text-cyan-200">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" /> Free · No login · No data
              leaves your device
            </div>
            <h1 className="mt-4 max-w-3xl text-3xl font-bold tracking-tight text-white sm:text-4xl">
              Security tools for{" "}
              <span className="bg-gradient-to-r from-cyan-300 to-indigo-300 bg-clip-text text-transparent">
                MCP-based AI agents
              </span>
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-relaxed text-slate-400 sm:text-base">
              A working implementation of the four MCPShield defense layers. Scan tool definitions
              for poisoning, cryptographically attest tools to catch rug pulls, enforce
              capability-based access control, and track information flow across trust domains.
            </p>
            <div className="mt-6 flex flex-wrap gap-2">
              <button
                onClick={() => navigate("scanner")}
                className="rounded-xl bg-gradient-to-r from-cyan-400 to-indigo-500 px-5 py-2.5 text-sm font-semibold text-slate-950 shadow-lg shadow-indigo-500/20 transition hover:brightness-110"
              >
                🔍 Start scanning
              </button>
              <button
                onClick={() => {
                  document.getElementById("guide-content")?.scrollIntoView({ behavior: "smooth" });
                }}
                className="rounded-xl border border-white/15 bg-white/5 px-5 py-2.5 text-sm font-semibold text-white backdrop-blur transition hover:bg-white/10"
              >
                📋 Read the testing guide
              </button>
            </div>
          </div>
        </section>
      )}

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
