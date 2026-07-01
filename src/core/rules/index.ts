import type { Finding, Rule, ScanContext, Severity } from "../model";
import { SEVERITY_ORDER } from "../model";

import { rule as exposedPort } from "./exposed-port";
import { rule as privileged } from "./privileged";
import { rule as hostNetwork } from "./host-network";
import { rule as dockerSocket } from "./docker-socket";
import { rule as databasePortExposed } from "./database-port-exposed";
import { rule as plaintextSecret } from "./plaintext-secret";
import { rule as defaultSecretFallback } from "./default-secret-fallback";
import { rule as missingRestart } from "./missing-restart";
import { rule as missingHealthcheck } from "./missing-healthcheck";
import { rule as latestTag } from "./latest-tag";
import { rule as runsAsRoot } from "./runs-as-root";
import { rule as unpinnedImage } from "./unpinned-image";
import { rule as noUser } from "./no-user";
import { rule as missingResourceLimits } from "./missing-resource-limits";
import { rule as missingLabels } from "./missing-labels";
import { rule as cloudflaredNoAccess } from "./cloudflared-no-access";
import { rule as cloudflaredTunnelToRisky } from "./cloudflared-tunnel-to-risky";
import { rule as serviceNotes } from "./service-notes";

export const RULES: Rule[] = [
  exposedPort,
  privileged,
  hostNetwork,
  dockerSocket,
  databasePortExposed,
  plaintextSecret,
  defaultSecretFallback,
  missingRestart,
  missingHealthcheck,
  latestTag,
  runsAsRoot,
  unpinnedImage,
  noUser,
  missingResourceLimits,
  missingLabels,
  cloudflaredNoAccess,
  cloudflaredTunnelToRisky,
  serviceNotes,
];

// Derive the severity rank from the model's canonical ordering so the two can
// never drift apart.
const severityRank: Record<Severity, number> = SEVERITY_ORDER.reduce(
  (acc, severity, index) => {
    acc[severity] = index;
    return acc;
  },
  {} as Record<Severity, number>,
);

/**
 * Run every rule against the context and return all findings, sorted by
 * severity (high > medium > low > info), then service name, then ruleId.
 * A rule that throws is skipped so a single bad rule can't crash the scan.
 */
export function runRules(ctx: ScanContext, rules: Rule[] = RULES): Finding[] {
  const all: Finding[] = [];
  for (const rule of rules) {
    try {
      const findings = rule.run(ctx);
      for (const finding of findings) {
        all.push(finding);
      }
    } catch (err) {
      // A throwing rule must not crash the scan — but a security checker must
      // never silently drop a rule either. Surface it as a visible diagnostic.
      const message = err instanceof Error ? err.message : String(err);
      all.push({
        ruleId: "rule-error",
        severity: "info",
        title: `Rule "${rule.id}" failed and was skipped`,
        detail: `The rule threw an error, so its checks did not run and results may be incomplete: ${message}`,
        recommendation: `Please report this issue with the Compose file that triggered it.`,
      });
    }
  }

  all.sort((a, b) => {
    const sevDiff = severityRank[a.severity] - severityRank[b.severity];
    if (sevDiff !== 0) {
      return sevDiff;
    }
    const serviceA = a.service ?? "";
    const serviceB = b.service ?? "";
    if (serviceA !== serviceB) {
      return serviceA < serviceB ? -1 : 1;
    }
    if (a.ruleId !== b.ruleId) {
      return a.ruleId < b.ruleId ? -1 : 1;
    }
    return 0;
  });

  return all;
}
