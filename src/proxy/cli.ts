#!/usr/bin/env node
// MCPShield Proxy — CLI entry point.
// Usage:
//   npx mcpshield-proxy start --config ./my-mcp.json
//   npx mcpshield-proxy init   (creates a starter config)
//   npx mcpshield-proxy check  (dry-run static audit, no proxy started)

import { Command } from "commander";
import { MCPShieldProxy, loadProxyConfig } from "./server";
import { writeFileSync, existsSync } from "node:fs";
import { parseConfig, analyze, combineResults, loadConfig, analyzeWithLLM } from "./analyzer";

const program = new Command();

program
  .name("mcpshield-proxy")
  .description("Local security proxy for MCP servers")
  .version("1.0.0");

program
  .command("init")
  .description("Create a starter mcpshield.json config file")
  .option("-o, --out <path>", "output path", "./mcpshield.json")
  .action((opts) => {
    const path = opts.out;
    if (existsSync(path)) {
      console.error(`✗ ${path} already exists. Choose a different path or delete it.`);
      process.exit(1);
    }
    const sample = {
      mcpServers: {
        "filesystem": {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        },
        "github": {
          command: "npx",
          args: ["-y", "@modelcontextprotocol/server-github"],
          env: { GITHUB_PERSONAL_ACCESS_TOKEN: "ghp_replace_me" },
        },
      },
    };
    writeFileSync(path, JSON.stringify(sample, null, 2) + "\n");
    console.log(`✓ Wrote ${path}. Edit it, then run: mcpshield-proxy start --config ${path}`);
  });

program
  .command("check")
  .description("Run static analysis on a config without starting the proxy")
  .requiredOption("-c, --config <path>", "path to MCP config")
  .option("--llm", "also run LLM semantic analysis (requires GROQ_API_KEY env or stored key)")
  .action(async (opts) => {
    const raw = require("node:fs").readFileSync(opts.config, "utf8");
    const parsed = parseConfig(raw);
    if (!parsed.ok) {
      console.error(`✗ ${parsed.error.message}`);
      process.exit(1);
    }
    console.log(`Detected: ${parsed.format}  (${parsed.servers.length} server(s), ${parsed.servers.reduce((n, s) => n + s.tools.length, 0)} tool(s))`);
    const staticRes = analyze(parsed.servers, parsed.warnings);

    let llm: any = { enabled: false, used: false };
    if (opts.llm) {
      const cfg = loadConfig();
      if (!cfg) {
        console.error("✗ --llm requires a stored Groq API key. Run the browser app, set a key, then re-run.");
        process.exit(1);
      }
      llm = await analyzeWithLLM(parsed.servers, cfg);
    }

    const combined = combineResults(staticRes, llm);
    const grade = combined.combinedGrade;
    const color = grade === "A" ? "\x1b[32m" : grade === "B" ? "\x1b[32m" : grade === "C" ? "\x1b[33m" : grade === "D" ? "\x1b[33m" : "\x1b[31m";
    const reset = "\x1b[0m";
    console.log(`\n${color}Grade: ${grade}  ·  Risk score: ${combined.combinedScore}/100${reset}`);
    console.log(`  critical: ${staticRes.counts.critical}  high: ${staticRes.counts.high}  medium: ${staticRes.counts.medium}  low: ${staticRes.counts.low}  info: ${staticRes.counts.info}\n`);
    for (const f of staticRes.findings.slice(0, 20)) {
      const sev = f.severity.padEnd(8);
      console.log(`  [${sev}] ${f.tv}  ${f.rule}`);
      console.log(`            ${f.target}`);
      console.log(`            ${f.message}`);
      if (f.evidence) console.log(`            evidence: ${f.evidence.slice(0, 100)}`);
      console.log();
    }
    if (staticRes.findings.length > 20) console.log(`  … and ${staticRes.findings.length - 20} more\n`);
  });

program
  .command("start")
  .description("Start the MCPShield proxy")
  .requiredOption("-c, --config <path>", "path to MCP config")
  .option("-p, --port <number>", "port to listen on", "7777")
  .option("-m, --mode <mode>", "monitor (log only) or enforce (block bad calls)", "monitor")
  .action(async (opts) => {
    process.env.MCPSHIELD_PORT = String(opts.port);
    process.env.MCPSHIELD_MODE = opts.mode;
    const config = loadProxyConfig(opts.config);

    const proxy = new MCPShieldProxy(config);
    proxy.on("analysis", (e: any) => {
      const a = e.analysis;
      const g = a.combinedGrade;
      const c = g === "A" || g === "B" ? "\x1b[32m" : g === "C" ? "\x1b[33m" : "\x1b[31m";
      console.log(`${c}[${new Date().toLocaleTimeString()}] Scan: ${e.server} → Grade ${g} (${a.combinedScore}/100)${"\x1b[0m"}`);
    });
    proxy.on("call", (c: any) => {
      const cls = c.decision === "blocked" ? "\x1b[31m" : c.decision === "error" ? "\x1b[31m" : "\x1b[2m";
      console.log(`${cls}[${new Date().toLocaleTimeString()}] ${c.decision.toUpperCase()} ${c.server} ${c.method}${c.tool ? " " + c.tool : ""}${"\x1b[0m"}`);
    });
    proxy.on("upstream-exit", (e: any) => {
      console.error(`[!] Upstream ${e.server} exited with code ${e.code}`);
    });

    await proxy.listen();

    console.log(`To use this proxy, configure your MCP client to point at:`);
    console.log(`  http://localhost:${opts.port}/mcp/<server-name>\n`);
    console.log(`For example, in your claude_desktop_config.json, replace the existing mcpServers entries with:`);
    console.log(JSON.stringify({
      mcpServers: Object.fromEntries(
        Object.keys(config.upstream).map((n) => [n, {
          command: "npx",
          args: ["-y", "mcpshield-proxy", "mcp-bridge", n, "--proxy", `http://localhost:${opts.port}`],
        }])
      ),
    }, null, 2));
    console.log(`\nOr use the bridge mode: mcpshield-proxy mcp-bridge <server-name> --proxy <url>\n`);

    process.on("SIGINT", async () => {
      console.log("\nShutting down…");
      await proxy.close();
      process.exit(0);
    });
  });

// "mcp-bridge" mode: a tiny client that speaks stdio MCP, but forwards through the proxy.
// This lets users point Claude/Cursor at "npx mcpshield-proxy mcp-bridge <name>" and have
// it transparently route through the HTTP proxy.
program
  .command("mcp-bridge <server>")
  .description("stdio → HTTP proxy bridge (use as 'command' in your MCP client config)")
  .option("--proxy <url>", "proxy URL", "http://localhost:7777")
  .action(async (server, opts) => {
    const url = `${opts.proxy}/mcp/${encodeURIComponent(server)}`;
    let buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", async (chunk) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        try {
          const msg = JSON.parse(line);
          const res = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(msg),
          });
          const data = await res.json();
          process.stdout.write(JSON.stringify(data) + "\n");
        } catch (e) {
          process.stderr.write(`bridge error: ${(e as Error).message}\n`);
        }
      }
    });
  });

program.parse();
