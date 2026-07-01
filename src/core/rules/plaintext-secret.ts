import type { EnvEntry, Finding, Rule } from "../model";
import { isSecretKey, looksLikeSecretValue, redactValue } from "../secrets";

export const rule: Rule = {
  id: "plaintext-secret",
  description:
    "Flags plaintext secret values in service environments and .env files.",
  run(ctx) {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    const consider = (
      entry: EnvEntry,
      file: string,
      service: string | undefined,
    ): void => {
      if (entry.isReference) {
        return;
      }
      if (!isSecretKey(entry.key) || !looksLikeSecretValue(entry.value)) {
        return;
      }
      const dedupeKey = `${file}::${entry.key}`;
      if (seen.has(dedupeKey)) {
        return;
      }
      seen.add(dedupeKey);
      const finding: Finding = {
        ruleId: rule.id,
        severity: "high",
        title: `Plaintext secret "${entry.key}" in ${service ? "service environment" : "env file"}`,
        file,
        detail:
          `The key "${entry.key}" holds a hardcoded plaintext secret value. Committed secrets are easily leaked through version control, backups, and image layers.`,
        recommendation:
          "Use Docker secrets, keep secrets in an env file excluded from version control, or reference them via ${VAR} instead of hardcoding the value.",
        evidence: `${entry.key}=${redactValue(entry.value)}`,
      };
      if (service !== undefined) {
        finding.service = service;
      }
      findings.push(finding);
    };

    for (const service of ctx.services) {
      for (const entry of service.environment) {
        consider(entry, service.file, service.name);
      }
    }
    for (const envFile of ctx.envFiles) {
      for (const entry of envFile.entries) {
        consider(entry, envFile.path, undefined);
      }
    }

    return findings;
  },
};
