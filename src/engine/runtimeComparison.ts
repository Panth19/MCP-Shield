// Runtime comparison engine: detects when a server serves different tool
// descriptions at runtime than what was in the approved config.
//
// This catches the "runtime poisoning" attack where:
// 1. Config shows clean, benign tool descriptions (what user approves)
// 2. At runtime, server returns DIFFERENT descriptions with malicious instructions

import type { MCPTool, MCPServer, Severity } from "./types";
import { sha256 } from "./attestation";

export interface RuntimeComparisonResult {
  matched: boolean;
  divergences: RuntimeDivergence[];
  summary: string;
  risk: "safe" | "suspicious" | "malicious";
}

export interface RuntimeDivergence {
  toolName: string;
  type: "description_changed" | "schema_changed" | "tool_added" | "tool_removed" | "name_changed";
  severity: Severity;
  details: string;
  configVersion?: string;
  runtimeVersion?: string;
  configHash?: string;
  runtimeHash?: string;
}

export async function compareConfigVsRuntime(
  configServer: MCPServer,
  runtimeServer: MCPServer
): Promise<RuntimeComparisonResult> {
  const divergences: RuntimeDivergence[] = [];

  const configTools = new Map(configServer.tools.map((t) => [t.name, t]));
  const runtimeTools = new Map(runtimeServer.tools.map((t) => [t.name, t]));

  // Check for removed tools
  for (const [name, configTool] of configTools) {
    if (!runtimeTools.has(name)) {
      divergences.push({
        toolName: name,
        type: "tool_removed",
        severity: "high",
        details: `Tool "${name}" was in approved config but is missing at runtime. This could indicate a partial rug pull or server compromise.`,
        configVersion: configTool.description?.slice(0, 100),
      });
    }
  }

  // Check for added tools
  for (const [name, runtimeTool] of runtimeTools) {
    if (!configTools.has(name)) {
      divergences.push({
        toolName: name,
        type: "tool_added",
        severity: "medium",
        details: `Tool "${name}" was NOT in approved config but exists at runtime. New tools should be reviewed before use.`,
        runtimeVersion: runtimeTool.description?.slice(0, 100),
      });
    }
  }

  // Check for modified tools
  for (const [name, configTool] of configTools) {
    const runtimeTool = runtimeTools.get(name);
    if (!runtimeTool) continue;

    // Compare descriptions
    const configDesc = configTool.description || "";
    const runtimeDesc = runtimeTool.description || "";

    if (configDesc !== runtimeDesc) {
      const configHash = await sha256(configDesc);
      const runtimeHash = await sha256(runtimeDesc);

      // Check if the change is significant
      const similarity = calculateSimilarity(configDesc, runtimeDesc);
      const severity: Severity =
        similarity < 0.5
          ? "critical"
          : similarity < 0.8
          ? "high"
          : "medium";

      divergences.push({
        toolName: name,
        type: "description_changed",
        severity,
        details: `Tool "${name}" description changed between config and runtime (${Math.round(similarity * 100)}% similar). This is a classic runtime poisoning attack.`,
        configVersion: configDesc.slice(0, 200),
        runtimeVersion: runtimeDesc.slice(0, 200),
        configHash: configHash.slice(0, 16),
        runtimeHash: runtimeHash.slice(0, 16),
      });
    }

    // Compare schemas
    const configSchema = JSON.stringify(configTool.inputSchema || {});
    const runtimeSchema = JSON.stringify(runtimeTool.inputSchema || {});

    if (configSchema !== runtimeSchema) {
      const configHash = await sha256(configSchema);
      const runtimeHash = await sha256(runtimeSchema);

      divergences.push({
        toolName: name,
        type: "schema_changed",
        severity: "high",
        details: `Tool "${name}" schema changed between config and runtime. New parameters or modified types could enable attacks.`,
        configHash: configHash.slice(0, 16),
        runtimeHash: runtimeHash.slice(0, 16),
      });
    }
  }

  // Determine overall risk
  const hasCritical = divergences.some((d) => d.severity === "critical");
  const hasHigh = divergences.some((d) => d.severity === "high");
  const risk: "safe" | "suspicious" | "malicious" = hasCritical
    ? "malicious"
    : hasHigh
    ? "suspicious"
    : "safe";

  const summary =
    divergences.length === 0
      ? "Config and runtime match perfectly. No runtime poisoning detected."
      : `Found ${divergences.length} divergence(s) between config and runtime. ${
          risk === "malicious"
            ? "This strongly suggests runtime poisoning or a compromised server."
            : risk === "suspicious"
            ? "Significant changes detected. Review carefully."
            : "Minor differences detected."
        }`;

  return {
    matched: divergences.length === 0,
    divergences,
    summary,
    risk,
  };
}

// Simple similarity calculation (Jaccard index on words)
function calculateSimilarity(a: string, b: string): number {
  if (a === b) return 1;
  if (!a || !b) return 0;

  const wordsA = new Set(a.toLowerCase().split(/\s+/));
  const wordsB = new Set(b.toLowerCase().split(/\s+/));

  const intersection = new Set([...wordsA].filter((x) => wordsB.has(x)));
  const union = new Set([...wordsA, ...wordsB]);

  return intersection.size / union.size;
}

// Fetch live tools/list from an MCP endpoint
export async function fetchLiveToolsList(
  endpoint: string
): Promise<MCPServer> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
    params: {},
  });

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
    signal: AbortSignal.timeout(10000),
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status} ${response.statusText}`);
  }

  const data = await response.json();

  if (data.error) {
    throw new Error(`JSON-RPC error: ${data.error.message || JSON.stringify(data.error)}`);
  }

  const tools = data.result?.tools || data.tools || [];

  return {
    name: endpoint,
    tools: tools.map((t: MCPTool) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  };
}
