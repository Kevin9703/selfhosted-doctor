import type { Classification, Finding, Report } from "../core/model";

const SEVERITY_HEADINGS: Record<"high" | "medium" | "low", string> = {
  high: "## High Risk",
  medium: "## Medium Risk",
  low: "## Low Risk",
};

function classificationOf(f: Finding): Classification {
  return f.classification ?? "active";
}

function findingLine(f: Finding): string {
  const service = f.service ? `**${f.service}** ` : "";
  let line = `- ${service}${f.title} — ${f.detail}`;
  if (classificationOf(f) === "conditional" && f.profiles && f.profiles.length > 0) {
    line += ` _(only when profile \`${f.profiles.join("`, `")}\` is enabled)_`;
  }
  if (f.file) {
    line += ` (source: ${f.file})`;
  }
  if (f.evidence) {
    line += ` \`${f.evidence}\``;
  }
  return line;
}

/** Active findings of a given severity feed the High/Medium/Low sections. */
function severitySection(report: Report, severity: "high" | "medium" | "low"): string[] {
  const out: string[] = [SEVERITY_HEADINGS[severity], ""];
  const items = report.findings.filter(
    (f) => classificationOf(f) === "active" && f.severity === severity,
  );
  if (items.length === 0) {
    out.push("_None._");
  } else {
    for (const f of items) out.push(findingLine(f));
  }
  out.push("");
  return out;
}

function classificationSection(
  report: Report,
  classification: "conditional" | "template",
  heading: string,
  blurb: string,
): string[] {
  const out: string[] = [heading, ""];
  const items = report.findings.filter((f) => classificationOf(f) === classification);
  if (items.length === 0) {
    out.push("_None._");
  } else {
    out.push(blurb, "");
    for (const f of items) out.push(findingLine(f));
  }
  out.push("");
  return out;
}

export function renderMarkdown(report: Report): string {
  const lines: string[] = [];
  const { summary } = report;

  lines.push("# selfhosted-doctor report");
  lines.push("");

  // Summary
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Risk score: ${summary.riskScore}/100 (scored on active/selected services only)`);
  lines.push(`- Files scanned: ${report.files.length}`);
  if (report.files.length > 0) {
    for (const file of report.files) {
      lines.push(`  - ${file}`);
    }
  }
  const a = summary.active;
  const cnd = summary.conditional;
  const tpl = summary.template;
  lines.push(`- Active findings: ${a.high} high, ${a.medium} medium, ${a.low} low, ${a.info} info`);
  lines.push(
    `- Conditional findings (profile-gated, not scored): ${cnd.high} high, ${cnd.medium} medium, ${cnd.low} low`,
  );
  lines.push(`- Template findings (example/placeholder files): ${tpl.total} info`);
  lines.push("");

  // Active High / Medium / Low Risk
  lines.push(...severitySection(report, "high"));
  lines.push(...severitySection(report, "medium"));
  lines.push(...severitySection(report, "low"));

  // Conditional & Template
  lines.push(
    ...classificationSection(
      report,
      "conditional",
      "## Conditional Findings",
      "These apply only when the named optional Compose profile is enabled. Enable it with `--profile <name>` (or `--all-profiles`) to score it.",
    ),
  );
  lines.push(
    ...classificationSection(
      report,
      "template",
      "## Template Findings",
      "Default/placeholder secrets found in example template files. Copy the template to a real `.env`, then change every default before deploying.",
    ),
  );

  // Exposure Map
  lines.push("## Exposure Map");
  lines.push("");
  if (report.exposure.length === 0) {
    lines.push("_No published ports._");
  } else {
    lines.push("| Service | Host | Container | Protocol | Applies |");
    lines.push("| --- | --- | --- | --- | --- |");
    for (const e of report.exposure) {
      const host = e.hostIp && e.hostIp.length > 0 ? e.hostIp : "0.0.0.0";
      const applies =
        e.classification === "conditional" && e.profiles && e.profiles.length > 0
          ? `profile: ${e.profiles.join(", ")}`
          : "active";
      lines.push(`| ${e.service} | ${host}:${e.hostPort} | ${e.containerPort} | ${e.protocol} | ${applies} |`);
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
  // Active info-level notes (diagnostics, hygiene) — template info lives in its own section.
  const infoFindings = report.findings.filter(
    (f) => f.severity === "info" && classificationOf(f) !== "template",
  );
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
