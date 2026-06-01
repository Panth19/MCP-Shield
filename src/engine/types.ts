// Core domain types for the MCPShield toolkit.
// These mirror the Model Context Protocol (MCP) tool & server shapes.

export interface MCPToolParam {
  name: string;
  type?: string;
  description?: string;
  required?: boolean;
}

export interface MCPTool {
  name: string;
  description: string;
  // JSON-schema-ish input description
  inputSchema?: {
    type?: string;
    properties?: Record<string, { type?: string; description?: string }>;
    required?: string[];
  };
  // Free-form annotations some servers attach
  annotations?: Record<string, unknown>;
}

export interface MCPServer {
  name: string;
  version?: string;
  url?: string;
  transport?: "stdio" | "http" | "sse" | "https" | string;
  trustDomain?: string; // for L-IFT trust labeling
  tools: MCPTool[];
}

// ---- Scanner result types (L-RPE / MCP-Guard) ----

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  id: string;
  rule: string; // rule name
  tv: string; // threat vector id from the paper (e.g. TV1)
  severity: Severity;
  toolName: string;
  field: string; // where it was found (description / schema / name ...)
  message: string;
  evidence?: string; // the matched snippet
  recommendation: string;
}

export interface ScanResult {
  findings: Finding[];
  score: number; // 0-100 risk score (higher = riskier)
  grade: "A" | "B" | "C" | "D" | "F";
  toolCount: number;
  scannedAt: number;
  counts: Record<Severity, number>;
}

// ---- Attestation types (L-CTA) ----

export interface Attestation {
  toolName: string;
  serverName: string;
  version: string;
  hash: string; // SHA-256 of the canonical tool definition
  depsHash?: string;
  timestamp: number;
}

export type IntegrityStatus =
  | "unchanged"
  | "mutated"
  | "rolled-back"
  | "new"
  | "removed";

export interface IntegrityCheck {
  toolName: string;
  status: IntegrityStatus;
  oldHash?: string;
  newHash?: string;
  oldVersion?: string;
  newVersion?: string;
  detail: string;
}

// ---- Capability / Access control types (L-CAC) ----

export type Scope = "read" | "write" | "execute";

export interface Capability {
  id: string;
  tool: string; // tool name or "*"
  scope: Scope;
  allowedParams?: string[]; // restrict args; empty/undefined = any
  ttlSeconds?: number; // 0/undefined = no expiry
  issuedAt: number;
}

export interface CompositionRule {
  from: string; // tool name
  to: string; // tool name
  action: "allow" | "deny" | "audit";
  reason?: string;
}

export interface InvocationRequest {
  tool: string;
  args: string[]; // arg names being passed
  scope: Scope;
  previousTool?: string; // for composition checks
}

export interface AccessDecision {
  allowed: boolean;
  reasons: string[];
  warnings: string[];
  matchedCapability?: Capability;
  compositionRule?: CompositionRule;
}
