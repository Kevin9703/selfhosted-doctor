import type { Report, Severity } from "../core/model";
import { SEVERITY_ORDER } from "../core/model";
import pc from "picocolors";

// The set of color functions (red, green, bold, …) WITHOUT `createColors`, so
// both `pc` and the result of `pc.createColors(false)` are assignable to it.
type Colors = ReturnType<typeof pc.createColors>;

const SECTION_TITLES: Record<Severity, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

function colorSeverityHeader(c: Colors, severity: Severity, text: string): string {
  switch (severity) {
    case "high":
      return c.red(text);
    case "medium":
      return c.yellow(text);
    case "low":
      return c.cyan(text);
    default:
      return text;
  }
}

/**
 * Map a risk score to a color band. Higher is safer:
 *   67–100 → green, 34–66 → yellow, 0–33 → red.
 * Exported so the mapping can be tested without depending on a TTY.
 */
export function scoreColor(score: number): "green" | "yellow" | "red" {
  if (score >= 67) return "green";
  if (score >= 34) return "yellow";
  return "red";
}

function colorScore(c: Colors, score: number): string {
  const text = `${score}/100`;
  return c[scoreColor(score)](text);
}

export function renderTerminal(report: Report, opts?: { color?: boolean }): string {
  const c: Colors = opts?.color === false ? pc.createColors(false) : pc;
  const lines: string[] = [];

  lines.push(c.bold("selfhosted-doctor report"));
  lines.push("");

  lines.push(`Risk score: ${colorScore(c, report.summary.riskScore)}`);
  lines.push(`Files scanned: ${report.files.length}`);

  const counts = report.summary.counts;
  lines.push(`Findings: ${counts.high} high, ${counts.medium} medium, ${counts.low} low`);

  // Findings sections by severity, excluding info.
  for (const severity of SEVERITY_ORDER) {
    if (severity === "info") continue;
    const items = report.findings.filter((f) => f.severity === severity);
    lines.push("");
    lines.push(colorSeverityHeader(c, severity, SECTION_TITLES[severity]));
    if (items.length === 0) {
      lines.push("- none");
      continue;
    }
    for (const f of items) {
      const label = f.service ? `${f.service}: ${f.title}` : f.title;
      const suffix = f.file ? ` ${c.dim(`(${f.file})`)}` : "";
      lines.push(`- ${label}${suffix}`);
    }
  }

  // Exposure section.
  lines.push("");
  lines.push(c.bold("Exposure"));
  if (report.exposure.length === 0) {
    lines.push("- none");
  } else {
    for (const e of report.exposure) {
      const host = e.hostIp && e.hostIp.length > 0 ? e.hostIp : "0.0.0.0";
      lines.push(
        `- ${e.service}: ${host}:${e.hostPort} -> container:${e.containerPort} (${e.protocol})`,
      );
    }
  }

  // Diagnostics: rule failures are info-level (hidden from the sections above),
  // but a security checker must never silently drop a rule — surface them here.
  const diagnostics = report.findings.filter((f) => f.ruleId === "rule-error");
  if (diagnostics.length > 0) {
    lines.push("");
    lines.push(c.yellow("Diagnostics"));
    for (const f of diagnostics) {
      lines.push(`- ${f.title}${f.detail ? `: ${f.detail}` : ""}`);
    }
  }

  lines.push("");
  lines.push(
    c.dim(
      "Best-effort configuration checker, not a security guarantee. Review findings manually before exposing services.",
    ),
  );

  return lines.join("\n");
}
