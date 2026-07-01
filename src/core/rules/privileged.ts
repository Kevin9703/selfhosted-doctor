import type { Finding, Rule } from "../model";

export const rule: Rule = {
  id: "privileged",
  description: "Flags services running in privileged mode.",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      if (service.privileged === true) {
        findings.push({
          ruleId: rule.id,
          severity: "high",
          title: `Runs in privileged mode`,
          service: service.name,
          file: service.file,
          detail:
            `Service "${service.name}" runs with "privileged: true", which grants it nearly all host capabilities and effectively removes container isolation.`,
          recommendation:
            "Remove `privileged: true` and grant only the specific capabilities you need via `cap_add`.",
          evidence: "privileged: true",
        });
      }
    }
    return findings;
  },
};
