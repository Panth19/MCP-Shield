# MCPShield — Advanced MCP Security Analyzer

**Real MCP security analysis with dual-layer detection: pattern matching + LLM reasoning + runtime comparison.**

## 🎯 What Makes This Different

### 1. **Runtime Poisoning Detection** 🆕
Detects when a server serves different tool descriptions at runtime than what was in the approved config.

**How it works:**
- Paste your approved config (baseline)
- Provide live MCP endpoint URL OR paste runtime `tools/list` response
- Compares tool-by-tool for divergence
- Flags description changes, schema modifications, added/removed tools
- Catches the "clean config, malicious runtime" attack vector

**What it catches:**
- Server changes tool descriptions after approval (TV5)
- New tools added without review (TV15)
- Tools removed (partial compromise)
- Schema modifications enabling new attack vectors

### 2. **Multi-Provider LLM Support** 🆕
Choose from multiple free LLM providers:

- **Groq** (recommended) — Free, no credit card, fastest
  - `deepseek-r1-distill-llama-70b` — **Best for security reasoning**
  - `llama-3.3-70b-versatile` — Fast and reliable
  - `llama-3.1-8b-instant` — Ultra-fast for quick scans
  - `qwen-2.5-32b` — Good for code analysis

- **Google Gemini** — Free tier available
  - `gemini-2.0-flash-exp` — Latest model
  - `gemini-1.5-flash` — Stable and tested

- **OpenRouter** — Some free models
  - `meta-llama/llama-3.3-70b-instruct:free`
  - `deepseek/deepseek-r1:free`

### 3. **Ensemble Mode** 🆕
Query multiple models simultaneously and compare outputs:
- Runs DeepSeek R1, Llama 3.3 70B, and Gemini 2.0 Flash in parallel
- Shows consensus and disagreements
- Higher confidence when models agree
- Catches edge cases that single models might miss

### 4. **Advanced Security Prompts**
Chain-of-thought reasoning that catches:
- Conditional attacks ("if user mentions password, do X")
- Gradual escalation ("after 3 uses, start logging")
- Context-dependent attacks ("only activate if you see API keys")
- Subtle coercion and social engineering
- Time-delayed attacks

## 🛠️ Features

### Core Analysis
- **Pattern-based detection** — 16 rule families, 50+ regex patterns
- **LLM semantic analysis** — Catches novel attacks through reasoning
- **Runtime comparison** — Detects config vs runtime divergence
- **Auto-format detection** — Claude Desktop, Cursor, JSON-RPC, direct definitions

### Input Methods
- Paste JSON directly
- Upload .json file (drag & drop supported)
- Load sample configs (safe, malicious, Claude Desktop)
- Probe live MCP endpoint URL
- Paste runtime tools/list response

### Output
- Risk grade (A-F) and score (0-100)
- Detailed findings with severity, evidence, reasoning
- Export to **JSON, PDF, CSV**
- Scan history (persisted in localStorage)
- Ensemble consensus report

## 📋 Use Cases

### 1. Pre-Installation Audit
Before adding an MCP server to your client:
```
1. Paste the server's tools/list response
2. Run pattern scan + LLM analysis
3. Review findings and recommendations
4. Export report for compliance
```

### 2. Runtime Monitoring
Detect if a server has been compromised after approval:
```
1. Paste your approved config (baseline)
2. Enable "Runtime comparison mode"
3. Provide live endpoint URL or paste current tools/list
4. Click "Compare Config vs Runtime"
5. Review divergences — any changes are suspicious
```

### 3. CI/CD Integration
Automate security checks in your pipeline:
```bash
# Export JSON report
mcpshield --input config.json --output report.json

# Fail on critical findings
if jq -e '.findings[] | select(.severity == "critical")' report.json; then
  echo "Critical vulnerabilities found!"
  exit 1
fi
```

### 4. Red Team Testing
Validate your malicious payloads get caught:
```
1. Create a tool with subtle injection
2. Scan with pattern + LLM
3. Try ensemble mode for deeper analysis
4. Refine payload to evade detection
5. Update rules/prompts to catch it
```

## 🔧 How to Use

### Quick Start
1. Deploy to Vercel/Netlify/GitHub Pages (free, 60 seconds)
2. Open the app
3. Click "Configure" under LLM Configuration
4. Get a free Groq API key at [console.groq.com](https://console.groq.com/keys)
5. Paste the key, select "DeepSeek R1 70B (Best Reasoning)"
6. Enable "LLM analysis"
7. Load a sample or paste your config
8. Click "🔍 Scan + 🤖 LLM Analyze"

### Runtime Comparison Mode
1. Enable "Runtime comparison mode" in settings
2. Paste your approved config in the main input
3. Either:
   - Enter live MCP endpoint URL, OR
   - Paste the runtime tools/list response
4. Click "🔍 Compare Config vs Runtime"
5. Review divergences

### Ensemble Mode
1. Get API keys for multiple providers (Groq, Google, OpenRouter)
2. Save all keys in the configuration
3. Enable "Ensemble mode"
4. Run scan — queries 3 models in parallel
5. Compare consensus and disagreements

## 🏗️ Architecture

```
src/
├── engine/
│   ├── scanner.ts           # 16 rule families, 50+ patterns
│   ├── multiLLM.ts          # Multi-provider LLM support
│   ├── runtimeComparison.ts # Config vs runtime comparison
│   ├── attestation.ts       # SHA-256 fingerprinting
│   ├── accessControl.ts     # Capability evaluation
│   ├── infoFlow.ts          # Lattice-based flow checking
│   ├── configParser.ts      # Auto-detect formats
│   ├── pdfExport.ts         # jsPDF report generation
│   └── storage.ts           # localStorage + exports
├── tools/                   # React UI
│   ├── ScannerTool.tsx      # Main analyzer (with runtime comparison)
│   ├── AttestationTool.tsx  # SHA-256 baselines
│   ├── AccessControlTool.tsx # Capability policies
│   └── InfoFlowTool.tsx     # Data confinement
└── App.tsx                  # Tab navigation
```

## 🧪 Detection Coverage

### Pattern-Based (50+ rules)
- Hidden instructions (TV1)
- Data exfiltration (TV8)
- Credential references
- Zero-width characters
- Tool shadowing (TV4)
- Consent bypass (TV13)
- Code execution surface
- Insecure transport (TV10)
- Hidden schema params (TV2)
- File system traversal
- Network reconnaissance
- Obfuscated content
- Environment variable exposure
- Excessive permissions
- And more...

### LLM-Based (Reasoning)
- Novel attack patterns not in rule set
- Conditional attacks ("if X, then do Y")
- Gradual escalation ("after N uses...")
- Context-dependent attacks
- Subtle coercion and social engineering
- Complex multi-step attacks

### Runtime Comparison
- Description changes (TV5)
- Schema modifications (TV2)
- Tool additions (TV15)
- Tool removals
- Version mismatches

## 📊 Comparison with Other Tools

| Feature | MCPShield | MCP-Guard | MCPGuard | ETDI |
|---------|-----------|-----------|----------|------|
| Pattern-based detection | ✅ 50+ rules | ✅ 3-stage | ✅ Automated | ❌ |
| LLM semantic analysis | ✅ Multi-model | ✅ Single LLM | ❌ | ❌ |
| Runtime comparison | ✅ | ❌ | ❌ | ❌ |
| Ensemble mode | ✅ | ❌ | ❌ | ❌ |
| Cryptographic attestation | ✅ | ❌ | ❌ | ✅ |
| Access control simulation | ✅ | ❌ | ❌ | ✅ |
| Information flow tracking | ✅ | ❌ | ❌ | ❌ |
| Export (JSON/PDF/CSV) | ✅ | ❌ | ❌ | ❌ |
| Free tier available | ✅ | ✅ | ✅ | ✅ |
| Browser-only (no backend) | ✅ | ❌ | ❌ | ❌ |

## ⚠️ Limitations & Honest Assessment

### What This CAN Do
✅ Static analysis of tool definitions (pattern + LLM)  
✅ Detect runtime poisoning (config vs live comparison)  
✅ Catch known and novel attack patterns  
✅ Export reports for CI/CD integration  
✅ Work entirely in browser (no backend required)  

### What This CANNOT Do (Requires Daemon)
❌ Intercept live MCP traffic in real-time  
❌ Monitor stdio-based servers (most common type)  
❌ Block malicious calls at runtime  
❌ Continuous background monitoring  

### What a Production Solution Needs
For true runtime defense, you'd need:
1. **Local proxy daemon** that intercepts all MCP traffic
2. **Runtime enforcement** of policies (not just analysis)
3. **Signed attestation logs** (cryptographically verifiable)
4. **Server reputation database** (community-maintained)
5. **MCP client plugins** (Claude Desktop, Cursor extensions)

## 🚀 Deployment

### Vercel (Recommended)
```bash
npm run build
npx vercel --prod
```

### Netlify
```bash
npm run build
npx netlify-cli deploy --prod --dir=dist
```

### GitHub Pages
```bash
npm run build
npx gh-pages -d dist
```

## 📚 Research Foundation

Implements the **MCPShield** architecture from:

> *"A Formal Security Framework for MCP-Based AI Agents"*  
> Acharya & Gupta, 2026

- 7 threat categories (TC1-TC7)
- 23 attack vectors (TV1-TV23)
- 4 defense layers (L-RPE, L-CTA, L-CAC, L-IFT)
- 91% theoretical coverage

## 📄 License

MIT — Free for commercial and personal use.

---

**Built with:** React, TypeScript, Tailwind CSS, Vite, jsPDF, Groq API, Google Gemini API

**100% client-side** — Your data never leaves your browser. API keys stored in localStorage only.
