// Information Flow Tracking (L-IFT).
// Implements Property 2 (Data Confinement) over a security lattice.
// Defends TC3 (cross-server data leakage): TV8, TV9.

export type Level = "public" | "internal" | "confidential" | "restricted";

export const LEVELS: Level[] = ["public", "internal", "confidential", "restricted"];
const RANK: Record<Level, number> = {
  public: 0,
  internal: 1,
  confidential: 2,
  restricted: 3,
};

// can-flow-to relation:  a ⊑ b  iff rank(a) <= rank(b)
export function canFlowTo(from: Level, to: Level): boolean {
  return RANK[from] <= RANK[to];
}

export interface Datum {
  id: string;
  label: string; // human label e.g. "customer email"
  level: Level;
  origin: string; // originating trust domain / server
}

export interface FlowServer {
  name: string;
  clearance: Level; // highest level this server may receive
}

export interface FlowCheck {
  datum: Datum;
  target: FlowServer;
  allowed: boolean;
  needsDeclassification: boolean;
  message: string;
}

// Check whether a set of data may be sent to a target server.
export function checkFlow(data: Datum[], target: FlowServer, declassified: Set<string>): FlowCheck[] {
  return data.map((d) => {
    const ok = canFlowTo(d.level, target.clearance);
    if (ok) {
      return {
        datum: d,
        target,
        allowed: true,
        needsDeclassification: false,
        message: `"${d.label}" (${d.level}) ⊑ ${target.name} (${target.clearance}). Flow permitted.`,
      };
    }
    if (declassified.has(d.id)) {
      return {
        datum: d,
        target,
        allowed: true,
        needsDeclassification: true,
        message: `"${d.label}" exceeds ${target.name}'s clearance but was EXPLICITLY declassified. Flow permitted with audit.`,
      };
    }
    return {
      datum: d,
      target,
      allowed: false,
      needsDeclassification: true,
      message: `BLOCKED: "${d.label}" (${d.level}) cannot flow to ${target.name} (${target.clearance}). Cross-domain leak prevented (TV8/TV9).`,
    };
  });
}
