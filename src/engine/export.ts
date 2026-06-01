// Export utilities: JSON and PDF.

import type { AnalysisResult, Finding } from "./types";

export function exportJson(result: AnalysisResult): void {
  const payload = {
    generatedAt: new Date().toISOString(),
    combinedScore: result.combinedScore,
    combinedGrade: result.combinedGrade,
    durationMs: result.durationMs,
    static: {
      score: result.static.score,
      grade: result.static.grade,
      counts: result.static.counts,
      totalTools: result.static.totalTools,
      serverCount: result.static.servers.length,
      parserWarnings: result.static.parserWarnings,
      findings: result.static.findings,
    },
    llm: result.llm,
  };
  download(JSON.stringify(payload, null, 2), `mcpshield-audit-${Date.now()}.json`, "application/json");
}

// Generates a self-contained HTML "report" that the user can print to PDF via the browser's
// native print dialog. We use an HTML page because we get proper styling without any deps.
export function exportPdf(result: AnalysisResult): void {
  const html = buildReportHtml(result);
  const win = window.open("", "_blank");
  if (!win) {
    alert("Popup blocked — please allow popups for this site, then try again.");
    return;
  }
  win.document.write(html);
  win.document.close();
  // give the window a moment to render, then trigger the browser print dialog
  setTimeout(() => {
    win.focus();
    win.print();
  }, 300);
}

function buildReportHtml(r: AnalysisResult): string {
  const s = r.static;
  const gradeColor: Record<string, string> = {
    A: "#10b981", B: "#84cc16", C: "#f59e0b", D: "#fb923c", F: "#f43f5e",
  };
  const sevColor: Record<string, string> = {
    critical: "#f43f5e", high: "#fb923c", medium: "#f59e0b", low: "#38bdf8", info: "#94a3b8",
  };

  const findingsHtml = s.findings.map((f) => `
    <div style="border:1px solid #e2e8f0; border-left:6px solid ${sevColor[f.severity]}; border-radius:8px; padding:14px 18px; margin-bottom:10px; page-break-inside: avoid;">
      <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
        <span style="background:${sevColor[f.severity]}; color:white; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; text-transform:uppercase;">${f.severity}</span>
        <span style="background:#e0e7ff; color:#3730a3; padding:2px 8px; border-radius:4px; font-size:11px; font-family:monospace;">${f.tv}</span>
        <span style="font-weight:600; font-size:14px;">${escapeHtml(f.rule)}</span>
      </div>
      <div style="font-size:13px; color:#334155; margin-bottom:6px;">${escapeHtml(f.message)}</div>
      <div style="font-size:12px; color:#64748b; margin-bottom:6px;"><strong>Target:</strong> <code style="background:#f1f5f9; padding:1px 6px; border-radius:3px;">${escapeHtml(f.target)}</code></div>
      ${f.evidence ? `<pre style="background:#0f172a; color:#fda4af; padding:8px 12px; border-radius:6px; font-size:12px; overflow-x:auto; margin:6px 0;">${escapeHtml(f.evidence)}</pre>` : ""}
      <div style="font-size:12px; color:#475569; margin-top:6px;"><strong>Why it matters:</strong> ${escapeHtml(f.reasoning)}</div>
      <div style="font-size:12px; color:#059669; margin-top:4px;"><strong>Fix:</strong> ${escapeHtml(f.recommendation)}</div>
    </div>
  `).join("");

  const llmSection = r.llm.used
    ? r.llm.error
      ? `<div style="background:#fef2f2; border:1px solid #fecaca; border-radius:6px; padding:12px; color:#991b1b; font-size:13px; margin-bottom:20px;">LLM analysis failed: ${escapeHtml(r.llm.error)}</div>`
      : `<div style="background:#ecfdf5; border:1px solid #a7f3d0; border-radius:6px; padding:12px; color:#065f46; font-size:13px; margin-bottom:20px;">
           <strong>LLM semantic analysis completed</strong>${r.llm.model ? ` using <code>${escapeHtml(r.llm.model)}</code>` : ""}.
           ${r.llm.summary ? `<div style="margin-top:6px;">${escapeHtml(r.llm.summary)}</div>` : ""}
         </div>`
    : `<div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:12px; color:#475569; font-size:13px; margin-bottom:20px;">LLM analysis not run. Add a free Groq API key in the app to enable semantic analysis.</div>`;

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>MCPShield Audit Report</title>
<style>
  @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } .no-print { display: none; } }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 800px; margin: 0 auto; padding: 30px 20px; color: #1e293b; background: white; }
  h1 { font-size: 24px; margin-bottom: 4px; }
  .meta { color: #64748b; font-size: 13px; margin-bottom: 24px; }
  .grade { display:inline-flex; align-items:center; justify-content:center; width:80px; height:80px; border-radius:16px; background:${gradeColor[r.combinedGrade]}; color:white; font-size:36px; font-weight:800; margin-right:20px; vertical-align:middle; }
  .summary { display:flex; align-items:center; margin-bottom: 30px; padding: 20px; background: #f8fafc; border-radius: 12px; }
  .counts { display:grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin: 16px 0 30px; }
  .count { text-align:center; padding: 10px; border-radius: 8px; border: 1px solid #e2e8f0; }
  .count b { display:block; font-size: 22px; }
  .print-btn { background: #4f46e5; color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; font-size: 14px; }
  h2 { font-size: 18px; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; margin-top: 30px; }
  ul { padding-left: 20px; }
  li { margin: 4px 0; font-size: 13px; }
</style>
</head>
<body>

<div class="no-print" style="background:#eef2ff; border:1px solid #c7d2fe; padding:10px 16px; border-radius:8px; margin-bottom:20px; display:flex; justify-content:space-between; align-items:center;">
  <span style="font-size:13px; color:#3730a3;">📄 Use your browser's "Save as PDF" option in the print dialog. Set margins to "Minimum" for best results.</span>
  <button class="print-btn" onclick="window.print()">🖨 Print / Save PDF</button>
</div>

<h1>MCPShield Security Audit Report</h1>
<div class="meta">
  Generated ${new Date().toISOString()} · Scan took ${r.durationMs}ms · ${s.servers.length} server(s) · ${s.totalTools} tool(s)
</div>

<div class="summary">
  <div class="grade">${r.combinedGrade}</div>
  <div>
    <div style="font-size: 32px; font-weight: 700;">${r.combinedScore} / 100</div>
    <div style="color:#64748b; font-size:14px;">Combined risk score</div>
    <div style="color:#64748b; font-size:13px; margin-top:4px;">Static-only: ${s.score} · Grade ${s.grade} ${r.llm.used && !r.llm.error ? "· LLM-augmented" : ""}</div>
  </div>
</div>

<div class="counts">
  <div class="count" style="border-color:#fecdd3;"><b style="color:#f43f5e;">${s.counts.critical}</b><span style="font-size:11px; color:#64748b;">CRITICAL</span></div>
  <div class="count" style="border-color:#fed7aa;"><b style="color:#fb923c;">${s.counts.high}</b><span style="font-size:11px; color:#64748b;">HIGH</span></div>
  <div class="count" style="border-color:#fde68a;"><b style="color:#f59e0b;">${s.counts.medium}</b><span style="font-size:11px; color:#64748b;">MEDIUM</span></div>
  <div class="count" style="border-color:#bae6fd;"><b style="color:#38bdf8;">${s.counts.low}</b><span style="font-size:11px; color:#64748b;">LOW</span></div>
  <div class="count"><b style="color:#94a3b8;">${s.counts.info}</b><span style="font-size:11px; color:#64748b;">INFO</span></div>
</div>

<h2>Servers analyzed</h2>
<ul>
  ${s.servers.map((srv) => `<li><strong>${escapeHtml(srv.name)}</strong> (${srv.transport}) — ${srv.tools.length} tool(s) — format: ${escapeHtml(srv.sourceFormat)}</li>`).join("")}
</ul>

${llmSection}

<h2>Findings (${s.findings.length})</h2>
${findingsHtml || '<p style="color:#64748b;">No findings.</p>'}

${s.parserWarnings.length > 0 ? `<h2>Parser warnings</h2><ul>${s.parserWarnings.map((w) => `<li>${escapeHtml(w)}</li>`).join("")}</ul>` : ""}

<div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; color: #94a3b8; font-size: 11px; text-align: center;">
  Generated by MCPShield Toolkit · Free browser-based MCP security analyzer
</div>

</body>
</html>`;
}

function download(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : c === '"' ? "&quot;" : "&#39;"
  );
}

void ({} as Finding); // suppress unused import
