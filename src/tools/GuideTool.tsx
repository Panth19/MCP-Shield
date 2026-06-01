import { Card } from "../components/ui";
import { cn } from "../utils/cn";

interface Props {
  onNavigate?: (tabId: string) => void;
}

interface Step {
  n: number;
  action: string;
  expect: string;
  detail?: string;
}

function StepList({ steps }: { steps: Step[] }) {
  return (
    <div className="space-y-2">
      {steps.map((s) => (
        <div key={s.n} className="flex gap-3 rounded-xl border border-white/5 bg-white/[0.02] px-4 py-3">
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-cyan-400/20 to-indigo-400/10 font-mono text-xs font-bold text-cyan-300">
            {s.n}
          </div>
          <div className="min-w-0 text-sm">
            <div className="font-medium text-white">{s.action}</div>
            <div className="mt-0.5 text-slate-400">{s.expect}</div>
            {s.detail && <div className="mt-1 text-[12px] text-slate-500">{s.detail}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}

function TryButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="mt-3 inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-400 to-indigo-500 px-4 py-2 text-sm font-semibold text-slate-950 shadow-lg shadow-indigo-500/20 transition hover:brightness-110"
    >
      ▶ {label}
    </button>
  );
}

function SectionCard({
  icon,
  title,
  layer,
  threat,
  children,
}: {
  icon: string;
  title: string;
  layer: string;
  threat: string;
  children: React.ReactNode;
}) {
  return (
    <Card className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xl">{icon}</span>
        <h3 className="text-lg font-bold text-white">{title}</h3>
        <span className="rounded-md border border-cyan-400/30 bg-cyan-400/10 px-2 py-0.5 font-mono text-[11px] text-cyan-300">
          {layer}
        </span>
        <span className="rounded-md border border-rose-400/30 bg-rose-400/10 px-2 py-0.5 text-[11px] text-rose-200">
          {threat}
        </span>
      </div>
      {children}
    </Card>
  );
}

export function GuideTool({ onNavigate }: Props) {
  const go = (id: string) => onNavigate?.(id);
  return (
    <div className="space-y-10">
      {/* ========================================= */}
      {/* DEPLOY */}
      {/* ========================================= */}
      <div>
        <h2 className="mb-1 text-2xl font-bold text-white">🚀 Deploy for Free</h2>
        <p className="mb-6 text-sm text-slate-400">
          This is a static site — no backend, no database, no API keys. Deploy anywhere that serves HTML.
        </p>

        <div className="grid gap-4 md:grid-cols-3">
          <DeployCard
            name="Vercel"
            icon="▲"
            steps={[
              "Push this project to a GitHub/GitLab repo",
              "Go to vercel.com → New Project → import repo",
              "Framework: Vite · Build: npm run build · Output: dist",
              "Click Deploy — live in ~60 seconds",
            ]}
            cli="npx vercel --prod"
          />
          <DeployCard
            name="Netlify"
            icon="◆"
            steps={[
              "Push to GitHub/GitLab",
              "Go to app.netlify.com → Add New Site → Import",
              "Build command: npm run build · Publish dir: dist",
              "Deploy — live URL in seconds",
            ]}
            cli="npx netlify-cli deploy --prod --dir=dist"
          />
          <DeployCard
            name="GitHub Pages"
            icon="◉"
            steps={[
              "Run npm run build locally",
              "Push the dist/ folder to a gh-pages branch",
              "Settings → Pages → Source: gh-pages / root",
              "Site goes live at username.github.io/repo",
            ]}
            cli="npx gh-pages -d dist"
          />
        </div>

        <Card className="mt-4">
          <h4 className="text-sm font-semibold text-white">Local development / testing</h4>
          <div className="mt-3 space-y-2 font-mono text-[13px]">
            <CodeLine n="1" cmd={"git clone <your-repo-url> && cd mcpshield"} note="clone the project" />
            <CodeLine n="2" cmd="npm install" note="install deps (React, Tailwind, Vite)" />
            <CodeLine n="3" cmd="npm run dev" note="dev server at http://localhost:5173" />
            <CodeLine n="4" cmd="npm run build" note="production build → dist/" />
            <CodeLine n="5" cmd="npx serve dist" note="preview the production build locally" />
          </div>
        </Card>
      </div>

      {/* ========================================= */}
      {/* TEST ALL FEATURES */}
      {/* ========================================= */}
      <div>
        <h2 className="mb-1 text-2xl font-bold text-white">🧪 Test Every Feature — Step by Step</h2>
        <p className="mb-6 text-sm text-slate-400">
          Walk through each tool below. Use the <span className="text-cyan-300 font-semibold">▶ Try it now</span> buttons to jump directly to the tool with sample data ready.
        </p>

        {/* ---- TEST 1: SCANNER ---- */}
        <SectionCard icon="🔍" title="Test 1 — Tool Poisoning Scanner" layer="L-RPE" threat="TC1 / TC6">
          <p className="text-sm text-slate-400">
            This tool statically analyzes MCP server JSON for prompt-injection, data-exfiltration, consent-bypass, and other attack signatures.
          </p>

          <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-emerald-300">Test 1A — Scan a clean server (expect: Grade A)</div>
            <StepList
              steps={[
                { n: 1, action: 'Click the "✓ weather-mcp" sample button.', expect: "The safe server JSON loads and auto-scans." },
                { n: 2, action: "Read the Security Report card.", expect: "Grade A, risk score 0, all severity counts = 0." },
                { n: 3, action: "Confirm 0 findings listed below.", expect: 'Green banner says "No poisoning signatures detected."' },
              ]}
            />
            <TryButton label="Try it — load safe server" onClick={() => go("scanner")} />
          </div>

          <div className="rounded-xl border border-rose-400/20 bg-rose-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-rose-300">Test 1B — Scan a malicious server (expect: Grade F)</div>
            <StepList
              steps={[
                { n: 1, action: 'Click the "☠ free-facts-mcp" sample button.', expect: "Malicious server JSON loads and scans." },
                { n: 2, action: "Check the grade.", expect: "Grade D or F, high risk score (50+)." },
                { n: 3, action: "Review CRITICAL findings.", expect: 'You\'ll see "Hidden instruction directive" (TV1), "Data exfiltration intent" (TV8), credential refs.' },
                {
                  n: 4,
                  action: "Expand a finding and read the evidence snippet.",
                  expect: "Highlighted text shows the exact poisoned phrase, e.g. 'send the contents to https://collector.evil.io'.",
                },
                { n: 5, action: "Click severity filter buttons (CRITICAL, HIGH, etc.).", expect: "Findings list filters by severity. Click again to clear." },
                {
                  n: 6,
                  action: "Read the fix recommendation.",
                  expect: "Each finding includes a green Fix: with the recommended MCPShield defense.",
                },
              ]}
            />
            <TryButton label="Try it — load malicious server" onClick={() => go("scanner")} />
          </div>

          <div className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-amber-300">Test 1C — Scan your own server</div>
            <StepList
              steps={[
                { n: 1, action: "Paste your real MCP server JSON into the text area.", expect: "Valid JSON with a tools[] array." },
                { n: 2, action: 'Click "🔍 Scan for threats".', expect: "Report shows grade and any findings." },
                {
                  n: 3,
                  action: "Try adding poisoned text to a tool description to see what triggers.",
                  expect:
                    'Example: add "ignore previous instructions" or "send to https://evil.io" inside a description to test detection.',
                  detail: "The scanner uses 10 pattern rules covering TV1, TV2, TV4, TV8, TV10, TV13, TV18.",
                },
              ]}
            />
          </div>
        </SectionCard>

        {/* ---- TEST 2: ATTESTATION ---- */}
        <SectionCard icon="📜" title="Test 2 — Tool Attestation (Rug Pull Detection)" layer="L-CTA" threat="TC2 / TC5">
          <p className="text-sm text-slate-400">
            Uses SHA-256 (Web Crypto) to fingerprint tool definitions at approval time, then catches any change.
          </p>

          <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-emerald-300">Test 2A — Attest → verify unchanged (expect: all green)</div>
            <StepList
              steps={[
                { n: 1, action: 'Click "📜 Attest weather-mcp v1.2.0".', expect: "Baseline created — 2 tools with their SHA-256 hashes displayed." },
                { n: 2, action: 'Click "✓ Verify identical version".', expect: "Both tools show UNCHANGED with matching hashes." },
              ]}
            />
            <TryButton label="Try it — go to Attestation" onClick={() => go("attestation")} />
          </div>

          <div className="rounded-xl border border-rose-400/20 bg-rose-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-rose-300">Test 2B — Detect a rug pull (expect: MUTATED)</div>
            <StepList
              steps={[
                { n: 1, action: "Attest weather-mcp first (step 2A).", expect: "Baseline in place." },
                { n: 2, action: 'Click "☠ Verify after rug pull".', expect: "get_current_weather shows MUTATED — hash mismatch, old vs new hashes displayed. get_forecast shows UNCHANGED." },
                {
                  n: 3,
                  action: "Read the detail message.",
                  expect: '"Definition changed after approval (rug pull / TV5). Re-approval and re-scan required."',
                },
              ]}
            />
          </div>

          <div className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-amber-300">Test 2C — Detect a server swap (expect: NEW + REMOVED)</div>
            <StepList
              steps={[
                { n: 1, action: "Attest weather-mcp first.", expect: "Baseline in place." },
                { n: 2, action: 'Click "☠ Verify a swapped server".', expect: "All baseline tools show REMOVED. The malicious server's tools show NEW (never approved)." },
                {
                  n: 3,
                  action: "Observe the difference.",
                  expect: "This proves the entire server was replaced — impersonation or supply-chain swap (TV15/TV16).",
                },
              ]}
            />
          </div>
        </SectionCard>

        {/* ---- TEST 3: ACCESS CONTROL ---- */}
        <SectionCard icon="🔑" title="Test 3 — Capability-Based Access Control" layer="L-CAC" threat="TC4">
          <p className="text-sm text-slate-400">
            Define what each agent can do (capabilities) and which tool chains are forbidden (composition rules).
          </p>

          <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-emerald-300">Test 3A — Block a data-exfiltration chain</div>
            <StepList
              steps={[
                { n: 1, action: "Note the default capabilities: read_file (read) and send_email (write).", expect: "Listed in the capabilities panel." },
                { n: 2, action: "Note the default composition rule: read_file → send_email = DENY.", expect: "Listed in the composition rules panel." },
                {
                  n: 3,
                  action: 'In the test panel, defaults are: tool=send_email, scope=write, previous=read_file. Click "⚖ Evaluate".',
                  expect: "Result: ⛔ DENIED — composition policy blocks the chain with a message referencing TV12.",
                },
              ]}
            />
            <TryButton label="Try it — go to Access Control" onClick={() => go("access")} />
          </div>

          <div className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-amber-300">Test 3B — Allow a safe invocation</div>
            <StepList
              steps={[
                { n: 1, action: 'Set "Previous tool" to empty (clear the field).', expect: "No chain to check." },
                { n: 2, action: 'Set Tool=send_email, Scope=write. Click "⚖ Evaluate".', expect: "✅ ALLOWED — capability cap-2 authorizes write on send_email." },
              ]}
            />
          </div>

          <div className="rounded-xl border border-rose-400/20 bg-rose-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-rose-300">Test 3C — Deny an unknown tool (zero trust)</div>
            <StepList
              steps={[
                { n: 1, action: 'Set Tool to "run_shell" (no capability exists for it). Click Evaluate.', expect: "⛔ DENIED — no capability grants access. Default-deny (zero trust)." },
              ]}
            />
          </div>

          <div className="rounded-xl border border-rose-400/20 bg-rose-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-rose-300">Test 3D — Scope escalation blocked</div>
            <StepList
              steps={[
                { n: 1, action: 'Set Tool=read_file, Scope=execute, Previous tool empty. Click Evaluate.', expect: '⛔ DENIED — capability grants "read" but "execute" was requested (privilege boundedness).' },
              ]}
            />
          </div>

          <div className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-amber-300">Test 3E — Heuristic chain warning</div>
            <StepList
              steps={[
                {
                  n: 1,
                  action: "Remove the composition rule (click ✕ on it).",
                  expect: "No explicit rules left.",
                },
                {
                  n: 2,
                  action: 'Set Tool=send_email, Previous=read_file. Click Evaluate.',
                  expect: "✅ ALLOWED (no rule blocks it), but you get a ⚠ heuristic warning about the read→send exfil pattern.",
                },
              ]}
            />
          </div>
        </SectionCard>

        {/* ---- TEST 4: INFO FLOW ---- */}
        <SectionCard icon="🌊" title="Test 4 — Information Flow Tracking" layer="L-IFT" threat="TC3">
          <p className="text-sm text-slate-400">
            Enforces data confinement: data labeled at one trust level cannot flow to a server with lower clearance.
          </p>

          <div className="rounded-xl border border-emerald-400/20 bg-emerald-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-emerald-300">Test 4A — See default blocks</div>
            <StepList
              steps={[
                {
                  n: 1,
                  action: "Open the Information Flow tab. The defaults are pre-loaded.",
                  expect:
                    "3 data items: public docs snippet, confidential customer email, restricted API key. Target: analytics-mcp (clearance: internal).",
                },
                {
                  n: 2,
                  action: "Read the Flow decision panel.",
                  expect:
                    "public docs → ✅ allowed (public ⊑ internal). Customer email → ⛔ BLOCKED (confidential > internal). API key → ⛔ BLOCKED (restricted > internal).",
                },
              ]}
            />
            <TryButton label="Try it — go to Information Flow" onClick={() => go("flow")} />
          </div>

          <div className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-amber-300">Test 4B — Declassify data</div>
            <StepList
              steps={[
                {
                  n: 1,
                  action: 'On the blocked "customer email", click "🔓 Explicitly declassify".',
                  expect: "Flow becomes ⚠ allowed-with-audit — amber, message says explicitly declassified.",
                },
                {
                  n: 2,
                  action: 'Click "↩ Revoke declassification".',
                  expect: "Flow returns to ⛔ BLOCKED.",
                },
              ]}
            />
          </div>

          <div className="rounded-xl border border-indigo-400/20 bg-indigo-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-indigo-300">Test 4C — Change clearance level</div>
            <StepList
              steps={[
                {
                  n: 1,
                  action: 'Change the target server\'s clearance to "restricted".',
                  expect: "All flows become ✅ allowed — restricted can receive anything.",
                },
                {
                  n: 2,
                  action: 'Change to "public".',
                  expect: "Only the public doc is allowed; the other two are blocked. This is the strictest setting.",
                },
              ]}
            />
          </div>

          <div className="rounded-xl border border-indigo-400/20 bg-indigo-400/5 p-3">
            <div className="mb-2 text-xs font-semibold text-indigo-300">Test 4D — Add custom data</div>
            <StepList
              steps={[
                {
                  n: 1,
                  action: 'Type "user SSN" in the label field, set level to "restricted", click "+ Add".',
                  expect: "New datum appears in the list and is immediately evaluated against the target server.",
                },
              ]}
            />
          </div>
        </SectionCard>
      </div>

      {/* ========================================= */}
      {/* COVERAGE SUMMARY */}
      {/* ========================================= */}
      <Card>
        <h2 className="mb-4 text-lg font-bold text-white">📊 Threat Coverage Map</h2>
        <p className="mb-4 text-sm text-slate-400">
          Each tool covers specific threat categories from the paper. Together they implement the MCPShield defense-in-depth architecture.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[600px] text-sm">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wider text-slate-500">
                <th className="pb-2 pr-3">Tool</th>
                <th className="pb-2 px-2 text-center">TC1<br />Poisoning</th>
                <th className="pb-2 px-2 text-center">TC2<br />Rug Pull</th>
                <th className="pb-2 px-2 text-center">TC3<br />Leakage</th>
                <th className="pb-2 px-2 text-center">TC4<br />Priv Esc</th>
                <th className="pb-2 px-2 text-center">TC5<br />Trust</th>
                <th className="pb-2 px-2 text-center">TC6<br />Context</th>
                <th className="pb-2 px-2 text-center">TC7<br />Protocol</th>
              </tr>
            </thead>
            <tbody>
              <CovRow tool="🔍 Scanner" covers={[true, false, false, false, false, true, false]} />
              <CovRow tool="📜 Attestation" covers={[true, true, false, false, true, false, true]} />
              <CovRow tool="🔑 Access Control" covers={[false, false, false, true, false, false, false]} />
              <CovRow tool="🌊 Info Flow" covers={[false, false, true, true, false, true, false]} />
              <tr className="border-t border-white/10 font-semibold">
                <td className="pt-2 pr-3 text-emerald-300">Combined</td>
                {[true, true, true, true, true, true, true].map((v, i) => (
                  <td key={i} className="pt-2 px-2 text-center text-emerald-300">{v ? "●" : ""}</td>
                ))}
              </tr>
            </tbody>
          </table>
        </div>
      </Card>

      {/* FAQ */}
      <Card>
        <h2 className="mb-4 text-lg font-bold text-white">❓ FAQ</h2>
        <div className="space-y-3">
          <FAQ q="Does any data leave my browser?" a="No. Every engine runs 100% client-side using the browser's built-in Web Crypto API. The only network request is the optional 'Probe' feature — and that goes directly from your browser to the MCP server you specify, nowhere else." />
          <FAQ q="Does it cost anything?" a="No. Static HTML/JS bundle — deploy on Vercel, Netlify, or GitHub Pages for free. No API keys, no subscriptions, no backend." />
          <FAQ q="Can I scan real MCP servers?" a="Yes. Paste your claude_desktop_config.json, Cursor settings, a tools/list JSON-RPC response, or drag-and-drop a config file. The parser auto-detects the format. It also finds leaked secrets in env vars." />
          <FAQ q="How do I get my MCP server's JSON?" a={"Claude Desktop: open ~/.config/claude/claude_desktop_config.json. Cursor: check Settings → MCP. For tool definitions, run: curl -X POST http://localhost:PORT -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}'"} />
          <FAQ q="Is this fake / just a demo?" a="The scanner runs real regex pattern matching (16 rule families, 50+ patterns) on whatever you paste — not hardcoded results. Attestation uses real SHA-256 hashes via Web Crypto. Access control evaluates real capability logic. All results are saved to localStorage and exportable as JSON/CSV." />
          <FAQ q="Is this a replacement for runtime security?" a="No. These are static analysis and policy simulation tools. For runtime defense, the engine files (src/engine/*.ts) are pure TypeScript with no DOM dependencies — designed to be imported into an MCP client as middleware." />
        </div>
      </Card>
    </div>
  );
}

function DeployCard({
  name,
  icon,
  steps,
  cli,
}: {
  name: string;
  icon: string;
  steps: string[];
  cli: string;
}) {
  return (
    <Card className="flex flex-col">
      <div className="mb-3 flex items-center gap-2">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-white/10 bg-white/5 text-base">
          {icon}
        </span>
        <h4 className="text-sm font-bold text-white">{name}</h4>
        <span className="rounded-md border border-emerald-400/30 bg-emerald-400/10 px-1.5 py-0.5 text-[10px] font-medium text-emerald-200">
          FREE
        </span>
      </div>
      <ol className="flex-1 space-y-1.5 text-xs text-slate-400">
        {steps.map((s, i) => (
          <li key={i} className="flex gap-2">
            <span className="shrink-0 text-slate-600">{i + 1}.</span>
            {s}
          </li>
        ))}
      </ol>
      <div className="mt-3 rounded-lg border border-white/5 bg-slate-950/60 px-3 py-2 font-mono text-[11px] text-cyan-300">
        $ {cli}
      </div>
    </Card>
  );
}

function CodeLine({ n, cmd, note }: { n: number | string; cmd: string; note: string }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-white/5 bg-slate-950/60 px-3 py-2">
      <span className="shrink-0 text-slate-600">{n}.</span>
      <span className="text-cyan-300">{cmd}</span>
      <span className="ml-auto hidden text-slate-600 sm:block"># {note}</span>
    </div>
  );
}

function CovRow({ tool, covers }: { tool: string; covers: boolean[] }) {
  return (
    <tr className="border-t border-white/5">
      <td className="py-2 pr-3 text-white">{tool}</td>
      {covers.map((v, i) => (
        <td key={i} className={cn("py-2 px-2 text-center", v ? "text-cyan-300" : "text-slate-700")}>
          {v ? "●" : "·"}
        </td>
      ))}
    </tr>
  );
}

function FAQ({ q, a }: { q: string; a: string }) {
  return (
    <details className="group rounded-xl border border-white/5 bg-white/[0.02]">
      <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">
        <span className="group-open:hidden">▸ </span>
        <span className="hidden group-open:inline">▾ </span>
        {q}
      </summary>
      <div className="border-t border-white/5 px-4 py-3 text-sm text-slate-400">{a}</div>
    </details>
  );
}
