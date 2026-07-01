import type { Classification, Finding, Report, SeverityCounts, Severity } from "../core/model";
import pc from "picocolors";

// The set of color functions (red, green, bold, …) WITHOUT `createColors`, so
// both `pc` and the result of `pc.createColors(false)` are assignable to it.
type Colors = ReturnType<typeof pc.createColors>;

function classificationOf(f: Finding): Classification {
  return f.classification ?? "active";
}

function colorSeverity(c: Colors, severity: Severity, text: string): string {
  switch (severity) {
    case "high":
      return c.red(text);
    case "medium":
      return c.yellow(text);
    case "low":
      return c.cyan(text);
    default:
      return c.dim(text);
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

/** "1 high, 9 medium, 12 low" — only non-zero severities; "none" when empty. */
function compactCounts(counts: SeverityCounts): string {
  const parts: string[] = [];
  if (counts.high) parts.push(`${counts.high} high`);
  if (counts.medium) parts.push(`${counts.medium} medium`);
  if (counts.low) parts.push(`${counts.low} low`);
  if (counts.info) parts.push(`${counts.info} info`);
  return parts.length > 0 ? parts.join(", ") : "none";
}

function findingLine(c: Colors, f: Finding): string {
  const tag = colorSeverity(c, f.severity, f.severity.toUpperCase().padEnd(4));
  const label = f.service ? `${f.service}: ${f.title}` : f.title;
  const file = f.file ? ` ${c.dim(`(${f.file})`)}` : "";
  const profiles =
    classificationOf(f) === "conditional" && f.profiles && f.profiles.length > 0
      ? ` ${c.dim(`[needs profile: ${f.profiles.join(", ")}]`)}`
      : "";
  return `- ${tag}  ${label}${file}${profiles}`;
}

function exposureLine(c: Colors, e: Report["exposure"][number]): string {
  const host = e.hostIp && e.hostIp.length > 0 ? e.hostIp : "0.0.0.0";
  const profiles =
    e.classification === "conditional" && e.profiles && e.profiles.length > 0
      ? ` ${c.dim(`[needs profile: ${e.profiles.join(", ")}]`)}`
      : "";
  return `- ${e.service}: ${host}:${e.hostPort} -> container:${e.containerPort} (${e.protocol})${profiles}`;
}

/** The top few findings the user should address first, active before conditional. */
function fixFirst(report: Report): Finding[] {
  const rank = (f: Finding): number => {
    const cls = classificationOf(f);
    return cls === "active" ? 0 : cls === "conditional" ? 1 : 2;
  };
  const byRank = (a: Finding, b: Finding): number => rank(a) - rank(b);

  const highs = report.findings.filter((f) => f.severity === "high").sort(byRank);
  if (highs.length > 0) return highs.slice(0, 5);

  // No highs anywhere — fall back to the most urgent non-template mediums.
  return report.findings
    .filter((f) => f.severity === "medium" && classificationOf(f) !== "template")
    .sort(byRank)
    .slice(0, 3);
}

export function renderTerminal(report: Report, opts?: { color?: boolean }): string {
  const c: Colors = opts?.color === false ? pc.createColors(false) : pc;
  const lines: string[] = [];
  const { summary } = report;

  lines.push(c.bold("selfhosted-doctor report"));
  lines.push("");
  lines.push(`Risk score: ${colorScore(c, summary.riskScore)} ${c.dim("(active/selected services)")}`);
  lines.push(`Files scanned: ${report.files.length}`);
  lines.push(`Active findings: ${compactCounts(summary.active)}`);
  if (summary.conditional.total > 0) {
    lines.push(`Conditional findings: ${compactCounts(summary.conditional)} ${c.dim("(profile-gated, not scored)")}`);
  }
  if (summary.template.total > 0) {
    lines.push(`Template findings: ${compactCounts(summary.template)} ${c.dim("(example/placeholder files)")}`);
  }

  // Fix first — the prioritized short list.
  const first = fixFirst(report);
  lines.push("");
  lines.push(c.bold("Fix first"));
  if (first.length === 0) {
    lines.push(c.dim("- Nothing urgent: no high or medium findings in your active stack."));
  } else {
    for (const f of first) lines.push(findingLine(c, f));
  }

  const active = report.findings.filter((f) => classificationOf(f) === "active" && f.severity !== "info");
  const conditional = report.findings.filter((f) => classificationOf(f) === "conditional");
  const template = report.findings.filter((f) => classificationOf(f) === "template");

  // Active section.
  lines.push("");
  lines.push(c.bold("Active"));
  if (active.length === 0) {
    lines.push("- none");
  } else {
    for (const f of active) lines.push(findingLine(c, f));
  }

  // Conditional section (only when relevant).
  if (conditional.length > 0) {
    lines.push("");
    lines.push(c.bold("Conditional") + c.dim(" — apply only when an optional profile is enabled"));
    for (const f of conditional) lines.push(findingLine(c, f));
  }

  // Template section (only when relevant).
  if (template.length > 0) {
    lines.push("");
    lines.push(c.bold("Template") + c.dim(" — defaults in example/placeholder files; change before deploying"));
    for (const f of template) lines.push(findingLine(c, f));
  }

  // Exposure section.
  lines.push("");
  lines.push(c.bold("Exposure"));
  const activeExposure = report.exposure.filter((e) => (e.classification ?? "active") === "active");
  const conditionalExposure = report.exposure.filter((e) => e.classification === "conditional");
  if (report.exposure.length === 0) {
    lines.push("- none");
  } else {
    if (activeExposure.length > 0) {
      for (const e of activeExposure) lines.push(exposureLine(c, e));
    } else {
      lines.push("- none active");
    }
    if (conditionalExposure.length > 0) {
      lines.push(c.dim("Conditional exposure:"));
      for (const e of conditionalExposure) lines.push(exposureLine(c, e));
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
