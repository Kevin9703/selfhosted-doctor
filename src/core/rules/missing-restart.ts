import type { Finding, Rule } from "../model";

export const rule: Rule = {
  id: "missing-restart",
  description: "Flags services with no restart policy.",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      if (service.restart === undefined || service.restart === "") {
        findings.push({
          ruleId: rule.id,
          severity: "medium",
          title: `Has no restart policy`,
          service: service.name,
          file: service.file,
          detail:
            `Service "${service.name}" declares no restart policy, so it will not come back up automatically after a crash or host reboot.`,
          recommendation:
            "Add `restart: unless-stopped` so the service recovers automatically.",
        });
      }
    }
    return findings;
  },
};
