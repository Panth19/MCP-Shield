import { useCallback, useEffect, useMemo, useState } from "react";
import { scanServer } from "../engine/scanner";
import { parseConfig, probeMCPEndpoint } from "../engine/configParser";
import {
  analyzeWithLLM,
  toStandardFindings,
  AVAILABLE_MODELS,
  RECOMMENDED_MODELS,
  ensembleAnalysis,
  type LLMProvider,
  type LLMAnalysisResult,
} from "../engine/multiLLM";
import {
  compareConfigVsRuntime,
  fetchLiveToolsList,
  type RuntimeComparisonResult,
} from "../engine/runtimeComparison";
import { exportScanAsPdf } from "../engine/pdfExport";
import {
  addScanHistory,
  clearScanHistory,
  exportAsCsv,
  exportAsJson,
  getScanHistory,
  type ScanHistoryEntry,
} from "../engine/storage";
import type { Finding, MCPServer, ScanResult, Severity } from "../engine/types";
import { SAMPLE_SERVERS, SAMPLE_CONFIGS } from "../engine/samples";
import { Badge, Button, Card, inputCls, severityStyle } from "../components/ui";
import { cn } from "../utils/cn";

const API_KEYS_STORAGE = "mcpshield_api_keys";
const LLM_MODEL_STORAGE = "mcpshield_llm_model";
const LLM_PROVIDER_STORAGE = "mcpshield_llm_provider";

const gradeColor: Record<ScanResult["grade"], string> = {
  A: "text-emerald-300 border-emerald-400/40 bg-emerald-400/10",
  B: "text-lime-300 border-lime-400/40 bg-lime-400/10",
  C: "text-amber-300 border-amber-400/40 bg-amber-400/10",
  D: "text-orange-300 border-orange-400/40 bg-orange-400/10",
  F: "text-rose-300 border-rose-400/40 bg-rose-400/10",
};
const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export function ScannerTool() {
  const [text, setText] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [format, setFormat] = useState("");
  const [serverName, setServerName] = useState("");
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [probeUrl, setProbeUrl] = useState("");
  const [probing, setProbing] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [parseWarnings, setParseWarnings] = useState<string[]>([]);

  // LLM-specific state
  const [apiKeys, setApiKeys] = useState<Record<LLMProvider, string>>({
    groq: "",
    google: "",
    openrouter: "",
  });
  const [llmProvider, setLlmProvider] = useState<LLMProvider>("groq");
  const [llmModel, setLlmModel] = useState(RECOMMENDED_MODELS.best);
  const [useLLM, setUseLLM] = useState(false);
  const [useEnsemble, setUseEnsemble] = useState(false);
  const [llmAnalyzing, setLlmAnalyzing] = useState(false);
  const [llmResult, setLlmResult] = useState<LLMAnalysisResult | null>(null);
  const [ensembleResults, setEnsembleResults] = useState<LLMAnalysisResult[] | null>(null);
  const [showSettings, setShowSettings] = useState(false);

  // Runtime comparison state
  const [runtimeMode, setRuntimeMode] = useState(false);
  const [runtimeText, setRuntimeText] = useState("");
  const [runtimeUrl, setRuntimeUrl] = useState("");
  const [runtimeComparing, setRuntimeComparing] = useState(false);
  const [runtimeResult, setRuntimeResult] = useState<RuntimeComparisonResult | null>(null);

  useEffect(() => {
    setHistory(getScanHistory());
    const savedKeys = localStorage.getItem(API_KEYS_STORAGE);
    if (savedKeys) {
      try {
        setApiKeys(JSON.parse(savedKeys));
      } catch {
        // Invalid JSON, ignore
      }
    }
    const savedModel = localStorage.getItem(LLM_MODEL_STORAGE);
    if (savedModel) setLlmModel(savedModel);
    const savedProvider = localStorage.getItem(LLM_PROVIDER_STORAGE) as LLMProvider;
    if (savedProvider) setLlmProvider(savedProvider);
  }, []);

  const saveApiKeys = () => {
    localStorage.setItem(API_KEYS_STORAGE, JSON.stringify(apiKeys));
  };

  const clearApiKeys = () => {
    localStorage.removeItem(API_KEYS_STORAGE);
    setApiKeys({ groq: "", google: "", openrouter: "" });
  };

  const saveModel = (m: string) => {
    setLlmModel(m);
    localStorage.setItem(LLM_MODEL_STORAGE, m);
  };

  const saveProvider = (p: LLMProvider) => {
    setLlmProvider(p);
    localStorage.setItem(LLM_PROVIDER_STORAGE, p);
  };

  const runPatternScan = useCallback(
    (raw?: string) => {
      const src = raw ?? text;
      setError(null);
      setResult(null);
      setLlmResult(null);
      setEnsembleResults(null);
      setRuntimeResult(null);
      setFormat("");
      setParseWarnings([]);

      let parsed: ReturnType<typeof parseConfig>;
      try {
        parsed = parseConfig(src);
      } catch (e) {
        setError((e as Error).message);
        return null;
      }

      setFormat(parsed.format);
      setParseWarnings(parsed.warnings);

      if (parsed.servers.length === 0) {
        setError("No MCP servers found in the input.");
        return null;
      }

      const merged: MCPServer = {
        name: parsed.servers.map((s) => s.name).join(", "),
        tools: parsed.servers.flatMap((s) => s.tools),
      };

      setServerName(merged.name);
      const scanResult = scanServer(merged);
      setResult(scanResult);

      const entry: ScanHistoryEntry = {
        id: `scan-${Date.now()}`,
        serverName: merged.name,
        timestamp: Date.now(),
        grade: scanResult.grade,
        score: scanResult.score,
        findingCount: scanResult.findings.length,
        toolCount: scanResult.toolCount,
        inputJson: src.slice(0, 2000),
      };
      addScanHistory(entry);
      setHistory(getScanHistory());

      return { merged, scanResult };
    },
    [text]
  );

  const runLLMAnalysis = useCallback(
    async (raw?: string) => {
      const apiKey = apiKeys[llmProvider];
      if (!apiKey.trim()) {
        setError(`Please enter a ${llmProvider} API key first.`);
        return;
      }

      const src = raw ?? text;
      setLlmAnalyzing(true);
      setError(null);

      let parsed: ReturnType<typeof parseConfig>;
      try {
        parsed = parseConfig(src);
      } catch (e) {
        setError((e as Error).message);
        setLlmAnalyzing(false);
        return;
      }

      if (parsed.servers.length === 0) {
        setError("No MCP servers found in the input.");
        setLlmAnalyzing(false);
        return;
      }

      const allTools = parsed.servers.flatMap((s) => s.tools);

      if (useEnsemble) {
        // Ensemble mode: query multiple models
        const models = RECOMMENDED_MODELS.ensemble.map((modelId) => {
          const model = AVAILABLE_MODELS.find((m) => m.id === modelId);
          return {
            modelId,
            provider: model?.provider || "groq",
            apiKey: apiKeys[model?.provider || "groq"] || apiKey,
          };
        }).filter((m) => m.apiKey.trim());

        if (models.length === 0) {
          setError("No API keys configured for ensemble models.");
          setLlmAnalyzing(false);
          return;
        }

        const ensemble = await ensembleAnalysis(allTools, models);
        setEnsembleResults(ensemble.results);

        // Merge all findings
        const patternResult = scanServer({ name: "merged", tools: allTools } as MCPServer);
        const allLLMFindings = ensemble.results
          .filter((r) => r.success)
          .flatMap((r) => toStandardFindings(r.findings, serverName, r.model));

        const combined: ScanResult = {
          ...patternResult,
          findings: dedupe([...patternResult.findings, ...allLLMFindings]),
        };

        recalculateScore(combined);
        setResult(combined);
      } else {
        // Single model analysis
        const llmRes = await analyzeWithLLM(allTools, apiKey, llmModel, llmProvider);
        setLlmResult(llmRes);

        if (!llmRes.success) {
          setError(llmRes.error || "LLM analysis failed");
          setLlmAnalyzing(false);
          return;
        }

        const merged: MCPServer = {
          name: parsed.servers.map((s) => s.name).join(", "),
          tools: allTools,
        };
        setServerName(merged.name);

        const patternResult = scanServer(merged);
        const llmFindings: Finding[] = allTools.flatMap((t) =>
          toStandardFindings(llmRes.findings, t.name, llmRes.model)
        );

        const combined: ScanResult = {
          ...patternResult,
          findings: dedupe([...patternResult.findings, ...llmFindings]),
        };

        recalculateScore(combined);
        setResult(combined);
      }

      setLlmAnalyzing(false);
    },
    [text, apiKeys, llmModel, llmProvider, useEnsemble, serverName]
  );

  const runRuntimeComparison = useCallback(async () => {
    setRuntimeComparing(true);
    setError(null);

    try {
      // Parse config (baseline)
      const configParsed = parseConfig(text);
      if (configParsed.servers.length === 0) {
        setError("No servers found in config.");
        setRuntimeComparing(false);
        return;
      }

      const configServer = configParsed.servers[0];

      // Get runtime (either from URL or pasted text)
      let runtimeServer: MCPServer;
      if (runtimeUrl.trim()) {
        runtimeServer = await fetchLiveToolsList(runtimeUrl.trim());
      } else if (runtimeText.trim()) {
        const runtimeParsed = parseConfig(runtimeText);
        if (runtimeParsed.servers.length === 0) {
          setError("No servers found in runtime response.");
          setRuntimeComparing(false);
          return;
        }
        runtimeServer = runtimeParsed.servers[0];
      } else {
        setError("Please provide either a runtime URL or paste the runtime tools/list response.");
        setRuntimeComparing(false);
        return;
      }

      // Compare
      const comparison = await compareConfigVsRuntime(configServer, runtimeServer);
      setRuntimeResult(comparison);

      // Convert divergences to findings
      const divergenceFindings: Finding[] = comparison.divergences.map((d, i) => ({
        id: `RT${i}`,
        rule: `[Runtime] ${d.type.replace("_", " ")}`,
        tv: d.type === "description_changed" ? "TV5" : d.type === "tool_added" ? "TV15" : "TV5",
        severity: d.severity,
        toolName: d.toolName,
        field: "runtime",
        message: d.details,
        evidence: d.runtimeVersion || d.configVersion,
        recommendation:
          d.severity === "critical"
            ? "Do NOT use this server. It has been compromised."
            : "Review the changes carefully before proceeding.",
      }));

      // Merge with pattern scan
      const patternResult = scanServer(configServer);
      const combined: ScanResult = {
        ...patternResult,
        findings: dedupe([...patternResult.findings, ...divergenceFindings]),
      };

      recalculateScore(combined);
      setResult(combined);
      setServerName(configServer.name);
    } catch (e) {
      setError((e as Error).message);
    }

    setRuntimeComparing(false);
  }, [text, runtimeText, runtimeUrl]);

  const recalculateScore = (combined: ScanResult) => {
    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    let raw = 0;
    const weights: Record<Severity, number> = {
      critical: 40,
      high: 20,
      medium: 8,
      low: 3,
      info: 1,
    };
    combined.findings.forEach((f) => {
      counts[f.severity]++;
      raw += weights[f.severity];
    });
    combined.counts = counts;
    combined.score = Math.min(100, raw);
    combined.grade =
      combined.score === 0
        ? "A"
        : combined.score < 15
        ? "B"
        : combined.score < 35
        ? "C"
        : combined.score < 60
        ? "D"
        : "F";
  };

  const dedupe = (findings: Finding[]): Finding[] => {
    const seen = new Set<string>();
    return findings.filter((f) => {
      const key = `${f.toolName}|${f.rule}|${f.field}|${f.evidence?.slice(0, 50)}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  };

  const loadSample = (key: string) => {
    const sample = SAMPLE_SERVERS[key];
    const json = JSON.stringify(sample, null, 2);
    setText(json);
  };

  const loadSampleConfig = (key: string) => {
    setText(SAMPLE_CONFIGS[key]);
  };

  const handleProbe = async () => {
    if (!probeUrl.trim()) return;
    setProbing(true);
    setError(null);
    try {
      const res = await probeMCPEndpoint(probeUrl);
      const json = JSON.stringify(
        { name: probeUrl, tools: res.servers.flatMap((s) => s.tools) },
        null,
        2
      );
      setText(json);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setProbing(false);
    }
  };

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setText(reader.result as string);
    reader.readAsText(file);
  }, []);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setText(reader.result as string);
    reader.readAsText(file);
  }, []);

  const filtered = useMemo(
    () => (result ? result.findings.filter((f) => filter === "all" || f.severity === filter) : []),
    [result, filter]
  );

  const handleExportJson = () => {
    if (!result) return;
    exportAsJson(
      {
        serverName,
        scannedAt: new Date(result.scannedAt).toISOString(),
        format,
        grade: result.grade,
        score: result.score,
        toolCount: result.toolCount,
        counts: result.counts,
        llmAnalysis: llmResult
          ? {
              model: llmResult.model,
              provider: llmResult.provider,
              latencyMs: llmResult.latencyMs,
              summary: llmResult.summary,
              overallRisk: llmResult.overallRisk,
              reasoning: llmResult.reasoning,
              findings: llmResult.findings,
            }
          : null,
        ensembleAnalysis: ensembleResults
          ? ensembleResults.map((r) => ({
              model: r.model,
              provider: r.provider,
              success: r.success,
              overallRisk: r.overallRisk,
              summary: r.summary,
              findings: r.findings,
            }))
          : null,
        runtimeComparison: runtimeResult
          ? {
              matched: runtimeResult.matched,
              risk: runtimeResult.risk,
              summary: runtimeResult.summary,
              divergences: runtimeResult.divergences,
            }
          : null,
        findings: result.findings,
      },
      `mcpshield-report-${serverName.replace(/[^a-z0-9]/gi, "-")}-${Date.now()}.json`
    );
  };

  const handleExportPdf = () => {
    if (!result) return;
    exportScanAsPdf(
      result,
      serverName,
      llmResult?.summary || ensembleResults?.[0]?.summary,
      llmResult?.reasoning || ensembleResults?.[0]?.reasoning
    );
  };

  const handleExportCsv = () => {
    if (!result) return;
    exportAsCsv(
      result.findings.map((f) => ({
        severity: f.severity,
        threatVector: f.tv,
        rule: f.rule,
        tool: f.toolName,
        field: f.field,
        evidence: f.evidence ?? "",
        recommendation: f.recommendation,
      })),
      `mcpshield-report-${serverName.replace(/[^a-z0-9]/gi, "-")}-${Date.now()}.csv`
    );
  };

  const modelsForProvider = AVAILABLE_MODELS.filter((m) => m.provider === llmProvider);

  return (
    <div className="space-y-6">
      {/* API Keys & Model Selection */}
      <Card>
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">🤖 LLM Configuration</h3>
            <p className="mt-0.5 text-xs text-slate-400">
              Pattern matching catches known attacks. LLM analysis catches novel attacks through reasoning.
            </p>
          </div>
          <button
            onClick={() => setShowSettings(!showSettings)}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-xs text-slate-300 hover:bg-white/10"
          >
            {showSettings ? "Hide" : "Configure"} ▾
          </button>
        </div>

        {showSettings && (
          <div className="mt-4 space-y-4 rounded-xl border border-white/5 bg-white/[0.02] p-4">
            {/* Provider Selection */}
            <div>
              <label className="mb-1 block text-xs font-semibold text-slate-400">Provider</label>
              <div className="flex gap-2">
                {(["groq", "google", "openrouter"] as LLMProvider[]).map((p) => (
                  <button
                    key={p}
                    onClick={() => saveProvider(p)}
                    className={cn(
                      "rounded-lg border px-3 py-1.5 text-xs font-medium transition",
                      llmProvider === p
                        ? "border-cyan-400/50 bg-cyan-400/10 text-cyan-200"
                        : "border-white/10 bg-white/5 text-slate-400 hover:bg-white/10"
                    )}
                  >
                    {p.charAt(0).toUpperCase() + p.slice(1)}
                  </button>
                ))}
              </div>
            </div>

            {/* API Key */}
            <div>
              <label className="mb-1 block text-xs font-semibold text-slate-400">
                {llmProvider.charAt(0).toUpperCase() + llmProvider.slice(1)} API Key
              </label>
              <div className="flex gap-2">
                <input
                  type="password"
                  value={apiKeys[llmProvider]}
                  onChange={(e) => setApiKeys({ ...apiKeys, [llmProvider]: e.target.value })}
                  placeholder={
                    llmProvider === "groq"
                      ? "gsk_..."
                      : llmProvider === "google"
                      ? "AIza..."
                      : "sk-or-..."
                  }
                  className={cn(inputCls, "flex-1")}
                />
                <Button variant="ghost" onClick={saveApiKeys} disabled={!apiKeys[llmProvider].trim()}>
                  Save
                </Button>
                {apiKeys[llmProvider] && (
                  <button
                    onClick={clearApiKeys}
                    className="rounded-lg border border-rose-400/20 bg-rose-500/5 px-3 py-2 text-xs text-rose-300 hover:bg-rose-500/10"
                  >
                    Clear
                  </button>
                )}
              </div>
              <p className="mt-1.5 text-[11px] text-slate-500">
                {llmProvider === "groq" && (
                  <>
                    Get free key at{" "}
                    <a
                      href="https://console.groq.com/keys"
                      target="_blank"
                      rel="noreferrer"
                      className="text-cyan-400 hover:underline"
                    >
                      console.groq.com
                    </a>
                    . No credit card required.
                  </>
                )}
                {llmProvider === "google" && (
                  <>
                    Get free key at{" "}
                    <a
                      href="https://aistudio.google.com/apikey"
                      target="_blank"
                      rel="noreferrer"
                      className="text-cyan-400 hover:underline"
                    >
                      aistudio.google.com
                    </a>
                    .
                  </>
                )}
                {llmProvider === "openrouter" && (
                  <>
                    Get key at{" "}
                    <a
                      href="https://openrouter.ai/keys"
                      target="_blank"
                      rel="noreferrer"
                      className="text-cyan-400 hover:underline"
                    >
                      openrouter.ai
                    </a>
                    . Some models are free.
                  </>
                )}
              </p>
            </div>

            {/* Model Selection */}
            <div>
              <label className="mb-1 block text-xs font-semibold text-slate-400">Model</label>
              <div className="space-y-1.5">
                {modelsForProvider.map((m) => (
                  <label
                    key={m.id}
                    className={cn(
                      "flex cursor-pointer items-start gap-2 rounded-lg border p-2 transition",
                      llmModel === m.id
                        ? "border-cyan-400/50 bg-cyan-400/5"
                        : "border-white/5 bg-white/[0.02] hover:bg-white/[0.04]"
                    )}
                  >
                    <input
                      type="radio"
                      checked={llmModel === m.id}
                      onChange={() => saveModel(m.id)}
                      className="mt-0.5"
                    />
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-white">{m.name}</span>
                        {m.id === RECOMMENDED_MODELS.best && (
                          <Badge className="border-emerald-400/30 bg-emerald-500/15 text-emerald-200">
                            Best Reasoning
                          </Badge>
                        )}
                        {m.id === RECOMMENDED_MODELS.fast && (
                          <Badge className="border-sky-400/30 bg-sky-500/15 text-sky-200">Fastest</Badge>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400">{m.description}</div>
                      <div className="text-[10px] text-slate-500">Best for: {m.bestFor}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {/* Analysis Mode */}
            <div className="space-y-2">
              <label className="flex cursor-pointer items-center gap-2">
                <input
                  type="checkbox"
                  checked={useLLM}
                  onChange={(e) => setUseLLM(e.target.checked)}
                  disabled={!apiKeys[llmProvider].trim()}
                  className="h-4 w-4 rounded border-white/20 bg-white/5 text-cyan-400 focus:ring-cyan-400"
                />
                <span className="text-sm text-slate-300">Enable LLM analysis</span>
              </label>

              <label className="flex cursor-pointer items-center gap-2">
                <input
                  type="checkbox"
                  checked={useEnsemble}
                  onChange={(e) => setUseEnsemble(e.target.checked)}
                  disabled={!useLLM}
                  className="h-4 w-4 rounded border-white/20 bg-white/5 text-cyan-400 focus:ring-cyan-400"
                />
                <div>
                  <span className="text-sm text-slate-300">Ensemble mode</span>
                  <span className="ml-2 text-[11px] text-slate-500">
                    (queries {RECOMMENDED_MODELS.ensemble.length} models, compares outputs)
                  </span>
                </div>
              </label>

              <label className="flex cursor-pointer items-center gap-2">
                <input
                  type="checkbox"
                  checked={runtimeMode}
                  onChange={(e) => setRuntimeMode(e.target.checked)}
                  className="h-4 w-4 rounded border-white/20 bg-white/5 text-cyan-400 focus:ring-cyan-400"
                />
                <div>
                  <span className="text-sm text-slate-300">Runtime comparison mode</span>
                  <span className="ml-2 text-[11px] text-slate-500">
                    (detects runtime poisoning)
                  </span>
                </div>
              </label>
            </div>
          </div>
        )}
      </Card>

      {/* Runtime Comparison Input */}
      {runtimeMode && (
        <Card>
          <h3 className="mb-2 text-sm font-semibold text-white">🔍 Runtime Comparison</h3>
          <p className="mb-3 text-xs text-slate-400">
            Compare approved config (baseline) against live server response to detect runtime poisoning.
          </p>

          <div className="space-y-3">
            <div>
              <label className="mb-1 block text-xs font-semibold text-slate-400">
                Live MCP Endpoint URL (optional)
              </label>
              <div className="flex gap-2">
                <input
                  value={runtimeUrl}
                  onChange={(e) => setRuntimeUrl(e.target.value)}
                  placeholder="https://mcp.example.com or http://localhost:3000"
                  className={cn(inputCls, "flex-1")}
                />
                <Button
                  variant="ghost"
                  onClick={runRuntimeComparison}
                  disabled={runtimeComparing || (!runtimeUrl.trim() && !runtimeText.trim())}
                >
                  {runtimeComparing ? "⏳ Comparing..." : "⚡ Fetch & Compare"}
                </Button>
              </div>
              <p className="mt-1 text-[11px] text-slate-500">
                Note: Most MCP servers are local (stdio) and can't be reached from browser due to CORS.
              </p>
            </div>

            <div>
              <label className="mb-1 block text-xs font-semibold text-slate-400">
                Or paste runtime tools/list response
              </label>
              <textarea
                value={runtimeText}
                onChange={(e) => setRuntimeText(e.target.value)}
                placeholder='Paste the JSON response from tools/list here...'
                className={cn(inputCls, "h-32 resize-none font-mono text-[12px]")}
              />
            </div>

            <Button
              onClick={runRuntimeComparison}
              disabled={runtimeComparing || (!runtimeUrl.trim() && !runtimeText.trim())}
            >
              {runtimeComparing ? "⏳ Comparing..." : "🔍 Compare Config vs Runtime"}
            </Button>
          </div>

          {runtimeResult && (
            <div
              className={cn(
                "mt-3 rounded-lg border p-3",
                runtimeResult.risk === "malicious"
                  ? "border-rose-400/30 bg-rose-500/10"
                  : runtimeResult.risk === "suspicious"
                  ? "border-amber-400/30 bg-amber-500/10"
                  : "border-emerald-400/30 bg-emerald-500/10"
              )}
            >
              <div className="flex items-center gap-2">
                <span className="text-lg">
                  {runtimeResult.matched ? "✅" : runtimeResult.risk === "malicious" ? "🚨" : "⚠️"}
                </span>
                <span className="text-sm font-semibold text-white">{runtimeResult.summary}</span>
              </div>
              {runtimeResult.divergences.length > 0 && (
                <div className="mt-2 space-y-1.5">
                  {runtimeResult.divergences.map((d, i) => (
                    <div key={i} className="rounded border border-white/5 bg-white/[0.02] p-2 text-xs">
                      <div className="flex items-center gap-2">
                        <Badge className={severityStyle[d.severity]}>{d.severity.toUpperCase()}</Badge>
                        <span className="font-semibold text-white">{d.toolName}</span>
                        <span className="text-slate-500">{d.type.replace("_", " ")}</span>
                      </div>
                      <p className="mt-1 text-slate-400">{d.details}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </Card>
      )}

      {/* Input Area */}
      <div className="grid gap-6 lg:grid-cols-2">
        <div
          className="relative"
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleFileDrop}
        >
          <Card>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-sm font-semibold text-white">
                {runtimeMode ? "Approved Config (Baseline)" : "Input"}
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {Object.keys(SAMPLE_SERVERS).map((k) => (
                  <button
                    key={k}
                    onClick={() => loadSample(k)}
                    className={cn(
                      "rounded-lg border px-2 py-1 text-[11px] font-medium transition",
                      k.startsWith("Malicious")
                        ? "border-rose-400/30 bg-rose-500/10 text-rose-200 hover:bg-rose-500/20"
                        : "border-emerald-400/30 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20"
                    )}
                  >
                    {k.startsWith("Malicious") ? "☠ " : "✓ "}
                    {k.split(":")[1].trim()}
                  </button>
                ))}
                {Object.entries(SAMPLE_CONFIGS).map(([label]) => (
                  <button
                    key={label}
                    onClick={() => loadSampleConfig(label)}
                    className="rounded-lg border border-indigo-400/30 bg-indigo-500/10 px-2 py-1 text-[11px] font-medium text-indigo-200 transition hover:bg-indigo-500/20"
                  >
                    📄 {label}
                  </button>
                ))}
              </div>
            </div>

            <div className="mb-2 rounded-lg border border-dashed border-white/10 bg-white/[0.02] px-3 py-2 text-[11px] text-slate-500">
              <span className="font-semibold text-slate-400">Auto-detects:</span> Claude Desktop · Cursor · JSON-RPC tools/list · {"{tools:[…]}"} · drag & drop .json files
            </div>

            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              spellCheck={false}
              placeholder={`Paste MCP server config here, or drag & drop a .json file.\n\nExamples:\n  • ~/.config/claude/claude_desktop_config.json\n  • A tools/list JSON-RPC response\n  • Direct definition: { "name": "...", "tools": [...] }`}
              className={cn(inputCls, "h-60 resize-none font-mono text-[12px] leading-relaxed")}
            />

            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Button
                onClick={() => {
                  if (runtimeMode) {
                    runPatternScan();
                  } else if (useLLM && apiKeys[llmProvider].trim()) {
                    runLLMAnalysis();
                  } else {
                    runPatternScan();
                  }
                }}
                disabled={!text.trim() || llmAnalyzing}
              >
                {llmAnalyzing
                  ? "🤖 Analyzing..."
                  : runtimeMode
                  ? "🔍 Scan Config"
                  : useLLM && apiKeys[llmProvider].trim()
                  ? "🔍 Scan + 🤖 LLM Analyze"
                  : "🔍 Pattern Scan"}
              </Button>
              <label className="cursor-pointer rounded-xl border border-white/15 bg-white/5 px-4 py-2 text-sm font-semibold text-white transition hover:bg-white/10">
                📁 Upload
                <input
                  type="file"
                  accept=".json,.jsonc,.txt"
                  className="hidden"
                  onChange={handleFileSelect}
                />
              </label>
              <Button
                variant="ghost"
                onClick={() => {
                  setText("");
                  setResult(null);
                  setLlmResult(null);
                  setEnsembleResults(null);
                  setRuntimeResult(null);
                  setError(null);
                  setFormat("");
                  setParseWarnings([]);
                }}
              >
                Clear
              </Button>
            </div>

            {/* Live probe */}
            <div className="mt-3 flex gap-2">
              <input
                className={cn(inputCls, "flex-1")}
                placeholder="http://localhost:PORT — probe a live MCP server"
                value={probeUrl}
                onChange={(e) => setProbeUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleProbe()}
              />
              <Button variant="ghost" onClick={handleProbe} disabled={probing || !probeUrl.trim()}>
                {probing ? "⏳" : "⚡"} Probe
              </Button>
            </div>

            {error && (
              <pre className="mt-3 whitespace-pre-wrap rounded-lg border border-rose-400/30 bg-rose-950/30 p-3 text-xs text-rose-200">
                {error}
              </pre>
            )}
            {parseWarnings.length > 0 &&
              parseWarnings.map((w, i) => (
                <div key={i} className="mt-2 flex gap-2 rounded-lg border border-amber-400/20 bg-amber-500/5 p-2 text-xs text-amber-200">
                  <span>⚠</span> {w}
                </div>
              ))}
          </Card>
        </div>

        {/* Report Summary */}
        <Card>
          <div className="mb-3 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Security Report</h3>
            {result && (
              <div className="flex gap-1.5">
                <button
                  onClick={handleExportJson}
                  className="rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-300 hover:bg-white/10"
                >
                  ⬇ JSON
                </button>
                <button
                  onClick={handleExportPdf}
                  className="rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-300 hover:bg-white/10"
                >
                  ⬇ PDF
                </button>
                <button
                  onClick={handleExportCsv}
                  className="rounded-lg border border-white/10 bg-white/5 px-2 py-1 text-[11px] text-slate-300 hover:bg-white/10"
                >
                  ⬇ CSV
                </button>
              </div>
            )}
          </div>

          {!result ? (
            <div className="flex h-60 flex-col items-center justify-center text-center text-sm text-slate-500">
              <span className="mb-3 text-4xl">🛡️</span>
              <p>Paste a config, upload a file, or load a sample.</p>
              <p className="mt-1 text-xs text-slate-600">
                {useLLM && apiKeys[llmProvider].trim()
                  ? useEnsemble
                    ? "Running ensemble analysis with multiple models."
                    : "Running pattern + LLM analysis."
                  : runtimeMode
                  ? "Configure runtime comparison above."
                  : "Configure API key above to enable LLM-powered detection."}
              </p>
            </div>
          ) : (
            <div>
              <div className="flex items-center gap-4">
                <div
                  className={cn(
                    "flex h-20 w-20 shrink-0 flex-col items-center justify-center rounded-2xl border-2",
                    gradeColor[result.grade]
                  )}
                >
                  <span className="text-3xl font-black">{result.grade}</span>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="truncate text-sm font-mono text-white">{serverName}</div>
                  <div className="text-2xl font-bold text-white">
                    {result.score}
                    <span className="text-base font-normal text-slate-500">/100</span>
                  </div>
                  <div className="text-xs text-slate-500">
                    {result.findings.length} findings · {result.toolCount} tools
                    {format && <span className="ml-1 text-cyan-400">· {format}</span>}
                  </div>
                </div>
              </div>

              {llmResult && llmResult.success && (
                <div className="mt-3 rounded-lg border border-indigo-400/30 bg-indigo-500/10 p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-indigo-200">
                      🤖 LLM Analysis ({llmResult.model}, {llmResult.latencyMs}ms)
                    </span>
                    <span
                      className={cn(
                        "rounded px-1.5 py-0.5 text-[10px] font-medium",
                        llmResult.overallRisk === "malicious"
                          ? "bg-rose-500/20 text-rose-200"
                          : llmResult.overallRisk === "suspicious"
                          ? "bg-amber-500/20 text-amber-200"
                          : "bg-emerald-500/20 text-emerald-200"
                      )}
                    >
                      {llmResult.overallRisk.toUpperCase()}
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs text-slate-200">{llmResult.summary}</p>
                  {llmResult.reasoning && (
                    <p className="mt-1 text-[11px] italic text-indigo-200/80">
                      Reasoning: {llmResult.reasoning}
                    </p>
                  )}
                </div>
              )}

              {ensembleResults && ensembleResults.length > 0 && (
                <div className="mt-3 rounded-lg border border-violet-400/30 bg-violet-500/10 p-3">
                  <div className="text-xs font-semibold text-violet-200">
                    🤖 Ensemble Analysis ({ensembleResults.length} models)
                  </div>
                  <div className="mt-2 space-y-1.5">
                    {ensembleResults.map((r, i) => (
                      <div key={i} className="flex items-center gap-2 text-[11px]">
                        <span
                          className={cn(
                            "rounded px-1 py-0.5 font-medium",
                            r.overallRisk === "malicious"
                              ? "bg-rose-500/20 text-rose-200"
                              : r.overallRisk === "suspicious"
                              ? "bg-amber-500/20 text-amber-200"
                              : "bg-emerald-500/20 text-emerald-200"
                          )}
                        >
                          {r.overallRisk.toUpperCase()}
                        </span>
                        <span className="text-slate-300">{r.model}</span>
                        <span className="text-slate-500">({r.latencyMs}ms)</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="mt-4 grid grid-cols-5 gap-2">
                {severityOrder.map((s) => (
                  <button
                    key={s}
                    onClick={() => setFilter(filter === s ? "all" : s)}
                    className={cn(
                      "rounded-xl border p-2 text-center transition",
                      result.counts[s] > 0
                        ? severityStyle[s]
                        : "border-white/5 bg-white/[0.02] text-slate-600",
                      filter === s && "ring-2 ring-white/40"
                    )}
                  >
                    <div className="text-lg font-bold">{result.counts[s]}</div>
                    <div className="text-[9px] uppercase tracking-wide">{s}</div>
                  </button>
                ))}
              </div>

              {filter !== "all" && (
                <button
                  onClick={() => setFilter("all")}
                  className="mt-2 text-[11px] text-cyan-400 hover:underline"
                >
                  ← Show all findings
                </button>
              )}

              {result.findings.length === 0 && (
                <div className="mt-4 rounded-xl border border-emerald-400/30 bg-emerald-500/10 p-4 text-sm text-emerald-200">
                  ✓ No security threats detected.
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      {/* Findings List */}
      {result && filtered.length > 0 && (
        <div className="space-y-3">
          {filtered.map((f) => {
            const isLLM = f.rule.includes("LLM") || f.rule.includes("[Runtime]");
            return (
              <Card key={f.id} className="border-l-4 border-l-transparent">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className={severityStyle[f.severity]}>{f.severity.toUpperCase()}</Badge>
                  <Badge className="border-white/15 bg-white/5 font-mono text-cyan-300">{f.tv}</Badge>
                  {isLLM && (
                    <Badge className="border-indigo-400/30 bg-indigo-500/15 text-indigo-200">
                      {f.rule.includes("[Runtime]") ? "🔍 Runtime" : "🤖 LLM"}
                    </Badge>
                  )}
                  <span className="text-sm font-semibold text-white">{f.rule}</span>
                  <span className="ml-auto rounded-md bg-white/5 px-2 py-0.5 font-mono text-[11px] text-slate-400">
                    {f.toolName} · {f.field}
                  </span>
                </div>
                <p className="mt-2 text-sm text-slate-300">{f.message}</p>
                {f.evidence && (
                  <pre className="mt-2 overflow-x-auto rounded-lg border border-rose-400/20 bg-rose-950/30 px-3 py-2 font-mono text-[12px] text-rose-200">
                    {f.evidence}
                  </pre>
                )}
                <p className="mt-2 text-xs text-emerald-300">
                  <span className="font-semibold">Fix: </span>
                  {f.recommendation}
                </p>
              </Card>
            );
          })}
        </div>
      )}

      {/* Scan History */}
      <Card>
        <div className="flex items-center justify-between">
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="flex items-center gap-2 text-sm font-semibold text-white"
          >
            <span>{showHistory ? "▾" : "▸"}</span>
            Scan History ({history.length})
          </button>
          {history.length > 0 && (
            <div className="flex gap-1.5">
              <button
                onClick={() => {
                  clearScanHistory();
                  setHistory([]);
                }}
                className="rounded-lg border border-rose-400/20 bg-rose-500/5 px-2 py-1 text-[11px] text-rose-300 hover:bg-rose-500/10"
              >
                🗑 Clear
              </button>
            </div>
          )}
        </div>
        {showHistory && (
          <div className="mt-3 space-y-1.5">
            {history.length === 0 && (
              <p className="text-xs text-slate-600">No scans yet.</p>
            )}
            {history.map((h) => (
              <button
                key={h.id}
                onClick={() => {
                  setText(h.inputJson);
                  runPatternScan(h.inputJson);
                }}
                className="flex w-full items-center gap-3 rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2 text-left text-xs transition hover:bg-white/[0.04]"
              >
                <span
                  className={cn(
                    "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border text-sm font-bold",
                    gradeColor[h.grade]
                  )}
                >
                  {h.grade}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium text-white">{h.serverName}</div>
                  <div className="text-slate-500">
                    {h.findingCount} findings · {h.toolCount} tools ·{" "}
                    {new Date(h.timestamp).toLocaleString()}
                  </div>
                </div>
                <span className="text-slate-600">↻</span>
              </button>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
