// PDF export for security scan reports.
// Uses jsPDF (client-side) — no server needed.

import jsPDF from "jspdf";
import type { ScanResult } from "./types";

export function exportScanAsPdf(
  result: ScanResult,
  serverName: string,
  llmSummary?: string,
  llmReasoning?: string
): void {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  const checkPageBreak = (neededSpace: number) => {
    if (y + neededSpace > doc.internal.pageSize.getHeight() - margin) {
      doc.addPage();
      y = margin;
    }
  };

  // Title
  doc.setFontSize(20);
  doc.setTextColor(20, 30, 50);
  doc.text("MCPShield Security Report", margin, y);
  y += 8;

  // Metadata
  doc.setFontSize(10);
  doc.setTextColor(100, 110, 130);
  doc.text(`Server: ${serverName}`, margin, y);
  y += 5;
  doc.text(`Scanned: ${new Date(result.scannedAt).toLocaleString()}`, margin, y);
  y += 5;
  doc.text(`Tools analyzed: ${result.toolCount}`, margin, y);
  y += 10;

  // Grade + Score
  doc.setFillColor(245, 247, 250);
  doc.rect(margin, y, contentWidth, 28, "F");
  doc.setFontSize(32);
  const gradeColors: Record<string, [number, number, number]> = {
    A: [16, 185, 129],
    B: [132, 204, 22],
    C: [245, 158, 11],
    D: [249, 115, 22],
    F: [239, 68, 68],
  };
  const gradeColor = gradeColors[result.grade] || [100, 100, 100];
  doc.setTextColor(...gradeColor);
  doc.text(result.grade, margin + 10, y + 20);

  doc.setFontSize(11);
  doc.setTextColor(60, 70, 90);
  doc.text(`Risk Score: ${result.score}/100`, margin + 35, y + 12);
  doc.text(
    `Findings: ${result.findings.length} (Critical: ${result.counts.critical}, High: ${result.counts.high}, Medium: ${result.counts.medium}, Low: ${result.counts.low})`,
    margin + 35,
    y + 19
  );
  y += 35;

  // LLM summary if present
  if (llmSummary) {
    checkPageBreak(30);
    doc.setFontSize(12);
    doc.setTextColor(20, 30, 50);
    doc.text("LLM Analysis Summary", margin, y);
    y += 6;

    doc.setFontSize(10);
    doc.setTextColor(60, 70, 90);
    const summaryLines = doc.splitTextToSize(llmSummary, contentWidth);
    doc.text(summaryLines, margin, y);
    y += summaryLines.length * 5 + 2;

    if (llmReasoning) {
      doc.setFont("helvetica", "italic");
      const reasoningLines = doc.splitTextToSize(`Reasoning: ${llmReasoning}`, contentWidth);
      doc.text(reasoningLines, margin, y);
      y += reasoningLines.length * 5 + 5;
    }
    doc.setFont("helvetica", "normal");
  }

  // Findings
  if (result.findings.length === 0) {
    checkPageBreak(20);
    doc.setFontSize(11);
    doc.setTextColor(16, 185, 129);
    doc.text("No security threats detected.", margin, y);
  } else {
    doc.setFontSize(12);
    doc.setTextColor(20, 30, 50);
    doc.text("Findings", margin, y);
    y += 8;

    const severityColors: Record<string, [number, number, number]> = {
      critical: [239, 68, 68],
      high: [249, 115, 22],
      medium: [245, 158, 11],
      low: [14, 165, 233],
      info: [100, 116, 139],
    };

    result.findings.forEach((f) => {
      const blockHeight = 38 + (f.evidence ? 12 : 0);
      checkPageBreak(blockHeight);

      // Finding box
      doc.setFillColor(250, 251, 253);
      doc.setDrawColor(220, 225, 235);
      doc.rect(margin, y, contentWidth, blockHeight - 3, "FD");

      // Severity badge
      const sevColor = severityColors[f.severity] || [100, 100, 100];
      doc.setFillColor(...sevColor);
      doc.rect(margin, y, 3, blockHeight - 3, "F");

      // Header line
      doc.setFontSize(9);
      doc.setTextColor(...sevColor);
      doc.setFont("helvetica", "bold");
      doc.text(f.severity.toUpperCase(), margin + 6, y + 5);
      doc.setFont("helvetica", "normal");

      doc.setTextColor(100, 110, 130);
      doc.text(`${f.tv} · ${f.toolName} · ${f.field}`, margin + 25, y + 5);

      // Rule name
      doc.setFontSize(10);
      doc.setTextColor(20, 30, 50);
      doc.setFont("helvetica", "bold");
      const ruleLines = doc.splitTextToSize(f.rule, contentWidth - 10);
      doc.text(ruleLines[0], margin + 6, y + 12);
      doc.setFont("helvetica", "normal");

      // Message
      doc.setFontSize(9);
      doc.setTextColor(60, 70, 90);
      const msgLines = doc.splitTextToSize(f.message, contentWidth - 10);
      let lineY = y + 18;
      msgLines.slice(0, 3).forEach((line: string) => {
        doc.text(line, margin + 6, lineY);
        lineY += 4;
      });

      // Evidence
      if (f.evidence) {
        lineY += 1;
        doc.setFillColor(254, 242, 242);
        doc.rect(margin + 6, lineY - 2, contentWidth - 12, 8, "F");
        doc.setFont("courier", "normal");
        doc.setFontSize(8);
        doc.setTextColor(185, 28, 28);
        const evLines = doc.splitTextToSize(f.evidence, contentWidth - 16);
        doc.text(evLines[0] || "", margin + 8, lineY + 3);
        doc.setFont("helvetica", "normal");
        lineY += 8;
      }

      // Recommendation
      doc.setFontSize(8);
      doc.setTextColor(16, 185, 129);
      const recLines = doc.splitTextToSize(`Fix: ${f.recommendation}`, contentWidth - 10);
      doc.text(recLines[0] || "", margin + 6, y + blockHeight - 7);

      y += blockHeight;
    });
  }

  // Footer
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 160, 180);
    doc.text(
      `MCPShield · Generated ${new Date().toLocaleString()} · Page ${i}/${pageCount}`,
      margin,
      doc.internal.pageSize.getHeight() - 8
    );
  }

  const filename = `mcpshield-report-${serverName.replace(/[^a-z0-9]/gi, "-")}-${Date.now()}.pdf`;
  doc.save(filename);
}
