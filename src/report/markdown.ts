import type { Report, Finding } from "../core/model";

const SEVERITY_HEADINGS: Record<"high" | "medium" | "low", string> = {
  high: "## High Risk",
  medium: "## Medium Risk",
  low: "## Low Risk",
};

function findingLine(f: Finding): string {
  const service = f.service ? `**${f.service}** ` : "";
  let line = `- ${service}${f.title} — ${f.detail}`;
  if (f.file) {
    line += ` (source: ${f.file})`;
  }
  if (f.evidence) {
    line += ` \`${f.evidence}\``;
  }
  return line;
}

function severitySection(report: Report, severity: "high" | "medium" | "low"): string[] {
  const out: string[] = [SEVERITY_HEADINGS[severity], ""];
  const items = report.findings.filter((f) => f.severity === severity);
  if (items.length === 0) {
    out.push("_None._");
  } else {
    for (const f of items) out.push(findingLine(f));
  }
  out.push("");
  return out;
}

export function renderMarkdown(report: Report): string {
  const lines: string[] = [];
  const counts = report.summary.counts;

  lines.push("# selfhosted-doctor report");
  lines.push("");

  // Summary
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Risk score: ${report.summary.riskScore}/100`);
  lines.push(`- Files scanned: ${report.files.length}`);
  if (report.files.length > 0) {
    for (const file of report.files) {
      lines.push(`  - ${file}`);
    }
  }
  lines.push(
    `- Findings: ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info, ${counts.total} total`,
  );
  lines.push("");

  // High / Medium / Low Risk
  lines.push(...severitySection(report, "high"));
  lines.push(...severitySection(report, "medium"));
  lines.push(...severitySection(report, "low"));

  // Exposure Map
  lines.push("## Exposure Map");
  lines.push("");
  if (report.exposure.length === 0) {
    lines.push("_No published ports._");
  } else {
    lines.push("| Service | Host | Container | Protocol |");
    lines.push("| --- | --- | --- | --- |");
    for (const e of report.exposure) {
      const host = e.hostIp && e.hostIp.length > 0 ? e.hostIp : "0.0.0.0";
      lines.push(`| ${e.service} | ${host}:${e.hostPort} | ${e.containerPort} | ${e.protocol} |`);
    }
  }
  lines.push("");

  // Service Notes
  lines.push("## Service Notes");
  lines.push("");
  if (report.services.length === 0) {
    lines.push("_None._");
  } else {
    lines.push("| Service | Type | Published ports | High | Med | Low |");
    lines.push("| --- | --- | --- | --- | --- | --- |");
    for (const s of report.services) {
      const type = s.detectedType ?? "";
      const high = s.findingCounts.high;
      const med = s.findingCounts.medium;
      const low = s.findingCounts.low;
      lines.push(
        `| ${s.name} | ${type} | ${s.publishedPorts} | ${high} | ${med} | ${low} |`,
      );
    }
  }
  const infoFindings = report.findings.filter((f) => f.severity === "info");
  if (infoFindings.length > 0) {
    lines.push("");
    for (const f of infoFindings) {
      lines.push(findingLine(f));
    }
  }
  lines.push("");

  // Suggested Fixes
  lines.push("## Suggested Fixes");
  lines.push("");
  const seen = new Set<string>();
  const fixes: string[] = [];
  for (const f of report.findings) {
    const rec = f.recommendation;
    if (!rec || rec.length === 0) continue;
    if (seen.has(rec)) continue;
    seen.add(rec);
    fixes.push(`- ${rec}`);
  }
  if (fixes.length === 0) {
    lines.push("_None._");
  } else {
    lines.push(...fixes);
  }
  lines.push("");

  // Disclaimer
  lines.push("## Disclaimer");
  lines.push("");
  lines.push(
    "This is a best-effort configuration checker, not a security guarantee. Review findings manually before exposing services.",
  );

  return lines.join("\n");
}
