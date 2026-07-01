import type { Finding, Rule } from "../model";

export const rule: Rule = {
  id: "missing-labels",
  description: "Flags services with no metadata labels.",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      if (Object.keys(service.labels).length === 0) {
        findings.push({
          ruleId: rule.id,
          severity: "info",
          title: `Has no labels`,
          service: service.name,
          file: service.file,
          detail:
            `Service "${service.name}" defines no labels, which makes it harder to attach metadata for tooling, reverse proxies, or backup selection.`,
          recommendation:
            "Add metadata `labels:` to document ownership and integrate with proxy/backup tooling.",
        });
      }
    }
    return findings;
  },
};
