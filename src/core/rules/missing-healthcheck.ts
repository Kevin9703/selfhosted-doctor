import type { Finding, Rule } from "../model";

export const rule: Rule = {
  id: "missing-healthcheck",
  description: "Flags services with no healthcheck defined.",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      if (!service.hasHealthcheck && !service.healthcheckDisabled) {
        findings.push({
          ruleId: rule.id,
          severity: "medium",
          title: `Has no healthcheck`,
          service: service.name,
          file: service.file,
          detail:
            `Service "${service.name}" defines no healthcheck, so Docker cannot tell whether the container is actually serving requests or just running.`,
          recommendation:
            "Add a `healthcheck:` so orchestration and dependent services can detect and react to failures.",
        });
      }
    }
    return findings;
  },
};
