// MCPShield Proxy — server-side analyzer.
// Re-uses the same static + LLM analysis logic as the browser app.
// This file has zero DOM dependencies and runs in Node.

import { analyze } from "../engine/analyzer";
import { parseConfig } from "../engine/parser";
import { analyzeWithLLM, loadConfig, saveConfig } from "../engine/llm";
import type { AnalysisResult, Finding, LLMAnalysis, NormalizedServer, StaticAnalysis } from "../engine/types";

export { analyze, parseConfig, analyzeWithLLM, loadConfig, saveConfig };
export type { AnalysisResult, Finding, LLMAnalysis, NormalizedServer, StaticAnalysis };

// Helper: combine static + LLM into final score (same logic as browser)
export function combineResults(s: StaticAnalysis, llm: LLMAnalysis): { combinedScore: number; combinedGrade: "A" | "B" | "C" | "D" | "F" } {
  let combinedScore = s.score;
  if (llm.used && !llm.error && llm.perTool) {
    const risks = Object.values(llm.perTool).map((v) => v.risk ?? 0);
    if (risks.length > 0) {
      const avg = risks.reduce((a, b) => a + b, 0) / risks.length;
      combinedScore = Math.round(s.score * 0.7 + Math.min(100, avg) * 0.3);
    }
  }
  const combinedGrade: "A" | "B" | "C" | "D" | "F" =
    combinedScore === 0 ? "A" : combinedScore < 12 ? "B" : combinedScore < 28 ? "C" : combinedScore < 55 ? "D" : "F";
  return { combinedScore, combinedGrade };
}
