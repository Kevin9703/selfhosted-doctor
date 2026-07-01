import type { Finding, Rule } from "../model";
import { isSecretKey, looksLikeSecretValue, redactValue } from "../secrets";

/**
 * Detect Compose fallback defaults for secret env vars, e.g.
 *   POSTGRES_PASSWORD: ${DB_PASSWORD:-difyai123456}
 *
 * A plain `${DB_PASSWORD}` reference is safe (the user must supply it), but a
 * `${VAR:-default}` fallback silently ships the hardcoded default whenever the
 * variable is unset — a classic self-hosted default-credential trap. This is a
 * distinct, high-value risk from a bare plaintext secret.
 */
export const rule: Rule = {
  id: "default-secret-fallback",
  description:
    "Flags secret env vars that fall back to a hardcoded default via ${VAR:-default}.",
  run(ctx) {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const service of ctx.services) {
      for (const entry of service.environment) {
        const fallback = entry.fallbackDefault;
        if (fallback === undefined) continue;
        if (!isSecretKey(entry.key) || !looksLikeSecretValue(fallback)) continue;

        const dedupeKey = `${service.file}::${service.name}::${entry.key}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);

        findings.push({
          ruleId: rule.id,
          severity: "high",
          service: service.name,
          file: service.file,
          title: `Default secret fallback for "${entry.key}" in service environment`,
          detail: `"${entry.key}" falls back to a hardcoded default when its variable is unset (\${VAR:-default}). A self-hoster who never sets this variable silently ships the known default credential.`,
          recommendation:
            "Set a strong, unique value for this variable and remove the hardcoded fallback default from the Compose file.",
          evidence: `${entry.key}=\${...:-${redactValue(fallback)}}`,
        });
      }
    }

    return findings;
  },
};
