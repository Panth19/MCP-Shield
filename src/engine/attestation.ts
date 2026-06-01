// Cryptographic Tool Attestation (L-CTA) + integrity checking.
// Uses the browser-native Web Crypto API (SHA-256) — no dependencies, fully free.
//
// Implements Property 1 (Tool Integrity): def_i(t) === def_approved(t)
// Defends: TC2 rug pulls (TV5 mutation, TV6 rollback), TV4 shadowing.

import type { Attestation, IntegrityCheck, MCPServer, MCPTool } from "./types";

// Canonicalize a tool definition so semantically-identical defs hash identically.
export function canonicalize(tool: MCPTool): string {
  const ordered = {
    name: tool.name ?? "",
    description: tool.description ?? "",
    inputSchema: sortKeys(tool.inputSchema ?? {}),
    annotations: sortKeys(tool.annotations ?? {}),
  };
  return JSON.stringify(ordered);
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return Object.keys(obj)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => {
        acc[k] = sortKeys(obj[k]);
        return acc;
      }, {});
  }
  return value;
}

export async function sha256(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function attestTool(
  tool: MCPTool,
  serverName: string,
  version = "1.0.0"
): Promise<Attestation> {
  const hash = await sha256(canonicalize(tool));
  return {
    toolName: tool.name,
    serverName,
    version,
    hash,
    timestamp: Date.now(),
  };
}

export async function attestServer(server: MCPServer): Promise<Attestation[]> {
  return Promise.all(
    server.tools.map((t) => attestTool(t, server.name, server.version ?? "1.0.0"))
  );
}

// Compare a known-good attestation log against a freshly observed server.
export async function checkIntegrity(
  baseline: Attestation[],
  current: MCPServer
): Promise<IntegrityCheck[]> {
  const baselineMap = new Map(baseline.map((a) => [a.toolName, a]));
  const currentAttestations = await attestServer(current);
  const currentMap = new Map(currentAttestations.map((a) => [a.toolName, a]));
  const checks: IntegrityCheck[] = [];

  // tools present now
  for (const cur of currentAttestations) {
    const base = baselineMap.get(cur.toolName);
    if (!base) {
      checks.push({
        toolName: cur.toolName,
        status: "new",
        newHash: cur.hash,
        newVersion: cur.version,
        detail:
          "Tool was NOT in the approved baseline. New, un-attested tools must be re-reviewed before use.",
      });
      continue;
    }
    if (base.hash === cur.hash) {
      checks.push({
        toolName: cur.toolName,
        status: "unchanged",
        oldHash: base.hash,
        newHash: cur.hash,
        oldVersion: base.version,
        newVersion: cur.version,
        detail: "Definition matches the approved attestation. Integrity verified.",
      });
    } else if (compareVersions(cur.version, base.version) < 0) {
      checks.push({
        toolName: cur.toolName,
        status: "rolled-back",
        oldHash: base.hash,
        newHash: cur.hash,
        oldVersion: base.version,
        newVersion: cur.version,
        detail: `Version regressed (${base.version} → ${cur.version}). Possible rollback to a vulnerable version (TV6).`,
      });
    } else {
      checks.push({
        toolName: cur.toolName,
        status: "mutated",
        oldHash: base.hash,
        newHash: cur.hash,
        oldVersion: base.version,
        newVersion: cur.version,
        detail:
          "Definition changed after approval (rug pull / TV5). Re-approval and re-scan required before this tool may run.",
      });
    }
  }

  // tools removed
  for (const base of baseline) {
    if (!currentMap.has(base.toolName)) {
      checks.push({
        toolName: base.toolName,
        status: "removed",
        oldHash: base.hash,
        oldVersion: base.version,
        detail: "Previously approved tool is no longer present.",
      });
    }
  }

  return checks;
}

function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d > 0 ? 1 : -1;
  }
  return 0;
}
