// Persistent storage layer using localStorage.
// Scan history, attestation baselines, and policies survive page refresh.

import type { Attestation, ScanResult } from "./types";

const PREFIX = "mcpshield_";

function get<T>(key: string): T | null {
  try {
    const raw = localStorage.getItem(PREFIX + key);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function set(key: string, value: unknown): void {
  try {
    localStorage.setItem(PREFIX + key, JSON.stringify(value));
  } catch {
    // localStorage full or unavailable — silent fail
  }
}

// --- Scan history ---

export interface ScanHistoryEntry {
  id: string;
  serverName: string;
  timestamp: number;
  grade: ScanResult["grade"];
  score: number;
  findingCount: number;
  toolCount: number;
  inputJson: string;
}

const HISTORY_KEY = "scan_history";
const MAX_HISTORY = 50;

export function getScanHistory(): ScanHistoryEntry[] {
  return get<ScanHistoryEntry[]>(HISTORY_KEY) ?? [];
}

export function addScanHistory(entry: ScanHistoryEntry): void {
  const history = getScanHistory();
  history.unshift(entry);
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  set(HISTORY_KEY, history);
}

export function clearScanHistory(): void {
  set(HISTORY_KEY, []);
}

// --- Attestation baselines ---

export interface StoredBaseline {
  id: string;
  name: string;       // e.g. "weather-mcp@1.2.0"
  timestamp: number;
  attestations: Attestation[];
  sourceJson: string;  // the original server JSON for re-verification
}

const BASELINES_KEY = "attestation_baselines";

export function getBaselines(): StoredBaseline[] {
  return get<StoredBaseline[]>(BASELINES_KEY) ?? [];
}

export function addBaseline(baseline: StoredBaseline): void {
  const all = getBaselines();
  // Replace if same name exists
  const idx = all.findIndex((b) => b.name === baseline.name);
  if (idx >= 0) all[idx] = baseline;
  else all.unshift(baseline);
  set(BASELINES_KEY, all);
}

export function removeBaseline(id: string): void {
  set(BASELINES_KEY, getBaselines().filter((b) => b.id !== id));
}

export function clearBaselines(): void {
  set(BASELINES_KEY, []);
}

// --- Export utilities ---

export function exportAsJson(data: unknown, filename: string): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportAsCsv(rows: Record<string, string | number>[], filename: string): void {
  if (rows.length === 0) return;
  const headers = Object.keys(rows[0]);
  const csv = [
    headers.join(","),
    ...rows.map((r) =>
      headers.map((h) => {
        const v = String(r[h] ?? "");
        return v.includes(",") || v.includes('"') || v.includes("\n")
          ? `"${v.replace(/"/g, '""')}"`
          : v;
      }).join(",")
    ),
  ].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
