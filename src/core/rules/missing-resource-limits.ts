import type { Finding, Rule } from "../model";

export const rule: Rule = {
  id: "missing-resource-limits",
  description: "Flags services with no memory/CPU resource limits.",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      if (!service.hasResourceLimits) {
        findings.push({
          ruleId: rule.id,
          severity: "info",
          title: `Has no resource limits`,
          service: service.name,
          file: service.file,
          detail:
            `Service "${service.name}" sets no memory or CPU limits, so a runaway container could starve other services on the host.`,
          recommendation:
            "Set memory and CPU limits (e.g. `mem_limit` / `cpus`, or `deploy.resources.limits`).",
        });
      }
    }
    return findings;
  },
};
