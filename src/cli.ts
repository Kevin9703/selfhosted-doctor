#!/usr/bin/env node
/**
 * selfhosted-doctor CLI.
 *
 *   selfhosted-doctor scan [path]
 *   selfhosted-doctor scan [path] --format markdown --output report.md
 *   selfhosted-doctor expose [path]
 *   selfhosted-doctor explain <report.json|path> --provider mock
 *   selfhosted-doctor mcp
 */
import { writeFileSync, readFileSync } from "node:fs";
import { Command } from "commander";
import pc from "picocolors";
import { scan } from "./core/scanner";
import { renderReport, type ReportFormat } from "./report";
import { renderExpose } from "./report/expose";
import { assessExposure } from "./core/verdict";
import { explainReport, type ExplainProvider } from "./ai/explain";
import { runMcpServer } from "./mcp/server";
import type { Report, Severity } from "./core/model";

const VERSION = "0.2.0";
const SEVERITIES: Severity[] = ["high", "medium", "low", "info"];

function inferFormat(output: string | undefined, explicit: string | undefined): ReportFormat {
  if (explicit) {
    if (explicit === "terminal" || explicit === "json" || explicit === "markdown") return explicit;
    throw new Error(`Unknown --format "${explicit}". Use terminal | json | markdown.`);
  }
  if (output) {
    if (output.endsWith(".json")) return "json";
    if (output.endsWith(".md") || output.endsWith(".markdown")) return "markdown";
  }
  return "terminal";
}

/** Exit code 1 when a finding at or above the threshold exists. */
function failThresholdTripped(report: Report, failOn: string): boolean {
  if (failOn === "none") return false;
  const idx = SEVERITIES.indexOf(failOn as Severity);
  if (idx < 0) return false;
  const atOrAbove = SEVERITIES.slice(0, idx + 1);
  return atOrAbove.some((sev) => report.summary.active[sev] > 0);
}

interface ScanFlags {
  format?: string;
  output?: string;
  color?: boolean;
  failOn: string;
  profile?: string[];
  allProfiles?: boolean;
}

function runScan(pathArg: string | undefined, flags: ScanFlags): void {
  const target = pathArg ?? ".";
  let report: Report;
  try {
    report = scan(target, { profiles: flags.profile, allProfiles: flags.allProfiles });
  } catch (err) {
    process.stderr.write(pc.red(`Error: ${err instanceof Error ? err.message : String(err)}\n`));
    process.exit(2);
  }

  const format = inferFormat(flags.output, flags.format);
  // Color only makes sense for terminal output going to a TTY.
  const color = flags.color !== false && format === "terminal" && !flags.output;
  const rendered = renderReport(report, format, { color });

  if (flags.output) {
    writeFileSync(flags.output, rendered.endsWith("\n") ? rendered : rendered + "\n", "utf8");
    process.stderr.write(pc.dim(`Report written to ${flags.output}\n`));
  } else {
    process.stdout.write(rendered + "\n");
  }

  if (failThresholdTripped(report, flags.failOn)) {
    process.exit(1);
  }
}

interface ExposeFlags {
  color?: boolean;
  profile?: string[];
  allProfiles?: boolean;
}

function runExpose(pathArg: string | undefined, flags: ExposeFlags): void {
  const target = pathArg ?? ".";
  let report: Report;
  try {
    report = scan(target, { profiles: flags.profile, allProfiles: flags.allProfiles });
  } catch (err) {
    process.stderr.write(pc.red(`Error: ${err instanceof Error ? err.message : String(err)}\n`));
    process.exit(2);
  }

  const assessment = assessExposure(report);
  const color = flags.color !== false;
  process.stdout.write(renderExpose(assessment, { color }) + "\n");

  // A genuine blocker (DON'T EXPOSE YET) exits non-zero so `expose` is usable as
  // a gate in scripts/CI. Every other verdict exits 0 — the decision is on stdout.
  if (assessment.verdict === "dont-expose") {
    process.exit(1);
  }
}

function runExplain(pathArg: string, provider: string): void {
  let report: Report;
  try {
    if (pathArg.endsWith(".json")) {
      report = JSON.parse(readFileSync(pathArg, "utf8")) as Report;
      if (!report || !Array.isArray(report.findings)) {
        throw new Error("File is not a selfhosted-doctor JSON report.");
      }
    } else {
      report = scan(pathArg);
    }
  } catch (err) {
    process.stderr.write(pc.red(`Error: ${err instanceof Error ? err.message : String(err)}\n`));
    process.exit(2);
  }

  try {
    process.stdout.write(explainReport(report, { provider: provider as ExplainProvider }) + "\n");
  } catch (err) {
    process.stderr.write(pc.red(`Error: ${err instanceof Error ? err.message : String(err)}\n`));
    process.exit(2);
  }
}

const program = new Command();

program
  .name("selfhosted-doctor")
  .description("AI-ready security checks for self-hosted homelabs, starting with Docker Compose.")
  .version(VERSION, "-v, --version");

program
  .command("scan", { isDefault: true })
  .description("Scan a Compose file or directory for homelab security risks.")
  .argument("[path]", "Compose file or directory to scan", ".")
  .option("-f, --format <format>", "Output format: terminal | json | markdown")
  .option("-o, --output <file>", "Write the report to a file instead of stdout")
  .option("--no-color", "Disable colored terminal output")
  .option(
    "--profile <name>",
    "Score/enable an optional Compose profile (repeatable)",
    (val: string, acc: string[]) => {
      acc.push(val);
      return acc;
    },
    [] as string[],
  )
  .option("--all-profiles", "Score every service, including all profile-gated ones")
  .option(
    "--fail-on <severity>",
    "Exit non-zero when a finding at or above this severity exists (high | medium | low | none)",
    "none",
  )
  .action((path: string | undefined, opts: ScanFlags) => {
    runScan(path, opts);
  });

program
  .command("expose")
  .description("Answer \"can I safely expose this to the internet?\" with a verdict and a short fix list.")
  .argument("[path]", "Compose file or directory to assess", ".")
  .option("--no-color", "Disable colored terminal output")
  .option(
    "--profile <name>",
    "Treat an optional Compose profile as active (repeatable)",
    (val: string, acc: string[]) => {
      acc.push(val);
      return acc;
    },
    [] as string[],
  )
  .option("--all-profiles", "Assess every service, including all profile-gated ones")
  .action((path: string | undefined, opts: ExposeFlags) => {
    runExpose(path, opts);
  });

program
  .command("explain")
  .description("Explain a scan result in plain language (AI explains findings, it never invents them).")
  .argument("<path>", "A selfhosted-doctor JSON report, or a Compose file/directory to scan first")
  .option("-p, --provider <provider>", "Explanation provider", "mock")
  .action((path: string, opts: { provider: string }) => {
    runExplain(path, opts.provider);
  });

program
  .command("mcp")
  .description("Run the read-only MCP server over stdio.")
  .action(async () => {
    await runMcpServer();
  });

program.parseAsync(process.argv).catch((err) => {
  process.stderr.write(pc.red(`Error: ${err instanceof Error ? err.message : String(err)}\n`));
  process.exit(2);
});
