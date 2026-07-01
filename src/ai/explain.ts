/**
 * AI explanation layer.
 *
 * IMPORTANT: AI never discovers findings. It only rephrases the deterministic
 * scanner output into plain language. The report is always the source of truth.
 *
 * The MVP ships a `mock` provider so the feature works offline with zero config
 * and leaks nothing to a network. Real providers (OpenAI/Anthropic/Ollama) can
 * be added behind the same `ExplainProvider` interface later.
 */
import type { Finding, Report, Severity } from "../core/model";

export type ExplainProvider = "mock";

export interface ExplainOptions {
  provider?: ExplainProvider;
}

const SEVERITY_LABEL: Record<Severity, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

function scoreVerdict(score: number): string {
  if (score >= 90) return "This setup looks fairly safe, but review the notes below before exposing anything.";
  if (score >= 70) return "This setup is mostly okay, but a few issues are worth fixing before you expose it.";
  if (score >= 40) return "This setup has meaningful risks. Fix the high-severity items before exposing services.";
  return "This setup is risky to expose as-is. Address the high-severity findings first.";
}

function explainFinding(finding: Finding): string {
  const who = finding.service ? `\`${finding.service}\`` : "your stack";
  const parts = [`- **${SEVERITY_LABEL[finding.severity]} — ${finding.title}** (${who}): ${finding.detail}`];
  if (finding.recommendation) {
    parts.push(`  - What to do: ${finding.recommendation}`);
  }
  return parts.join("\n");
}

/**
 * Produce a plain-language explanation of a report using the chosen provider.
 * The `mock` provider is deterministic and offline.
 */
export function explainReport(report: Report, opts: ExplainOptions = {}): string {
  const provider: ExplainProvider = opts.provider ?? "mock";
  if (provider !== "mock") {
    throw new Error(`Unknown AI provider "${provider}". Only "mock" is supported in this version.`);
  }

  const { counts, riskScore } = report.summary;
  const lines: string[] = [];
  lines.push(`# What selfhosted-doctor found`);
  lines.push("");
  lines.push(`Risk score: **${riskScore}/100**. ${scoreVerdict(riskScore)}`);
  lines.push("");
  lines.push(
    `There ${counts.total === 1 ? "is" : "are"} ${counts.total} finding${counts.total === 1 ? "" : "s"}: ` +
      `${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info.`,
  );
  lines.push("");

  const high = report.findings.filter((f) => f.severity === "high");
  const medium = report.findings.filter((f) => f.severity === "medium");

  if (high.length > 0) {
    lines.push(`## Fix these first (high risk)`);
    lines.push("");
    for (const f of high) lines.push(explainFinding(f));
    lines.push("");
  }

  if (medium.length > 0) {
    lines.push(`## Worth fixing soon (medium risk)`);
    lines.push("");
    for (const f of medium) lines.push(explainFinding(f));
    lines.push("");
  }

  if (high.length === 0 && medium.length === 0) {
    lines.push(`No high or medium risks were found. Review the lower-severity notes in the full report.`);
    lines.push("");
  }

  lines.push(
    `_Explanation generated from the deterministic scan (provider: ${provider}). ` +
      `The scanner — not the AI — decides what counts as a finding._`,
  );

  return lines.join("\n");
}
