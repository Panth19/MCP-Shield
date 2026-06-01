// Domain types for the MCP security analyzer.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface NormalizedTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  // the original raw object for debugging
  raw: Record<string, unknown>;
}

export interface NormalizedServer {
  name: string;
  version?: string;
  transport: "stdio" | "http" | "https" | "sse" | "websocket" | "unknown";
  url?: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  tools: NormalizedTool[];
  sourceFormat: string;
  warnings: string[];
  // raw input for re-export
  rawInput: unknown;
}

export interface Finding {
  id: string;
  rule: string;
  tv: string; // threat vector id
  severity: Severity;
  category: string;
  target: string; // server name, tool name, or config path
  message: string;
  evidence: string;
  reasoning: string; // why this matters
  recommendation: string;
  // where the finding was located
  location: {
    server?: string;
    tool?: string;
    field?: string;
    path?: string; // JSON path e.g. "$.mcpServers.github.env.GITHUB_TOKEN"
  };
}

export interface StaticAnalysis {
  findings: Finding[];
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  counts: Record<Severity, number>;
  servers: NormalizedServer[];
  totalTools: number;
  parsedAt: number;
  parserWarnings: string[];
}

export interface LLMAnalysis {
  enabled: boolean;
  used: boolean; // true if LLM was actually called
  model?: string;
  perTool?: Record<string, { risk: number; reasoning: string; flags: string[] }>;
  summary?: string;
  error?: string;
}

export interface AnalysisResult {
  static: StaticAnalysis;
  llm: LLMAnalysis;
  combinedScore: number;
  combinedGrade: "A" | "B" | "C" | "D" | "F";
  durationMs: number;
}

export interface ParseError {
  type: "json" | "schema" | "format";
  message: string;
  details?: string;
}
