// Capability-Based Access Control (L-CAC).
// Implements Property 3 (Privilege Boundedness) and composition policies that
// defend against TV12 (capability chaining) and TV13 (consent bypass).

import type {
  AccessDecision,
  Capability,
  CompositionRule,
  InvocationRequest,
  Scope,
} from "./types";

const SCOPE_RANK: Record<Scope, number> = { read: 1, write: 2, execute: 3 };

export function evaluateInvocation(
  req: InvocationRequest,
  capabilities: Capability[],
  rules: CompositionRule[]
): AccessDecision {
  const reasons: string[] = [];
  const warnings: string[] = [];

  // 1. Find a capability that covers this tool.
  const candidates = capabilities.filter((c) => c.tool === req.tool || c.tool === "*");
  if (candidates.length === 0) {
    return {
      allowed: false,
      reasons: [
        `No capability grants access to "${req.tool}". Default-deny (zero trust): unknown tools are blocked.`,
      ],
      warnings,
    };
  }

  let matched: Capability | undefined;
  for (const cap of candidates) {
    // scope check — granted scope must be >= requested scope
    if (SCOPE_RANK[cap.scope] < SCOPE_RANK[req.scope]) {
      reasons.push(
        `Capability ${cap.id} grants "${cap.scope}" but "${req.scope}" was requested (privilege boundedness).`
      );
      continue;
    }
    // ttl check
    if (cap.ttlSeconds && cap.ttlSeconds > 0) {
      const ageSec = (Date.now() - cap.issuedAt) / 1000;
      if (ageSec > cap.ttlSeconds) {
        reasons.push(`Capability ${cap.id} expired (${Math.round(ageSec)}s > TTL ${cap.ttlSeconds}s).`);
        continue;
      }
    }
    // param restriction check
    if (cap.allowedParams && cap.allowedParams.length > 0) {
      const disallowed = req.args.filter((a) => !cap.allowedParams!.includes(a));
      if (disallowed.length > 0) {
        reasons.push(
          `Capability ${cap.id} forbids parameter(s): ${disallowed.join(", ")}.`
        );
        continue;
      }
    }
    matched = cap;
    break;
  }

  if (!matched) {
    return { allowed: false, reasons, warnings };
  }
  reasons.push(`Capability ${matched.id} authorizes ${req.scope} on "${req.tool}".`);

  // 2. Composition / chaining check.
  let compositionRule: CompositionRule | undefined;
  if (req.previousTool) {
    compositionRule = rules.find(
      (r) => r.from === req.previousTool && (r.to === req.tool || r.to === "*")
    );
    if (compositionRule) {
      if (compositionRule.action === "deny") {
        return {
          allowed: false,
          reasons: [
            ...reasons,
            `Composition policy DENIES "${req.previousTool}" → "${req.tool}". ${compositionRule.reason ?? "Potential capability chaining (TV12)."}`,
          ],
          warnings,
          matchedCapability: matched,
          compositionRule,
        };
      }
      if (compositionRule.action === "audit") {
        warnings.push(
          `Composition "${req.previousTool}" → "${req.tool}" flagged for AUDIT. ${compositionRule.reason ?? ""}`
        );
      }
    }
  }

  // 3. Implicit chaining heuristic: read-then-external is a classic exfil chain.
  if (
    req.previousTool &&
    /read|get|fetch|list|search|load/i.test(req.previousTool) &&
    /send|post|email|upload|write|http|publish|webhook|notify/i.test(req.tool) &&
    !compositionRule
  ) {
    warnings.push(
      `Heuristic: "${req.previousTool}" (read) → "${req.tool}" (egress) resembles a data-exfiltration chain. Consider a composition rule.`
    );
  }

  if (req.scope === "execute") {
    warnings.push("Execute scope is high-impact — human confirmation recommended (consent enforcement, TV13).");
  }

  return { allowed: true, reasons, warnings, matchedCapability: matched, compositionRule };
}
