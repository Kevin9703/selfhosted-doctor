import type { Finding, Rule } from "../model";

export const rule: Rule = {
  id: "host-network",
  description: "Flags services using the host network namespace.",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      if (service.networkMode === "host") {
        findings.push({
          ruleId: rule.id,
          severity: "high",
          title: `Uses the host network`,
          service: service.name,
          file: service.file,
          detail:
            `Service "${service.name}" uses "network_mode: host", so it shares the host's network stack and bypasses Docker's port isolation and firewalling.`,
          recommendation:
            "Use a bridge network with explicit `ports:` mappings instead of `network_mode: host`.",
          evidence: "network_mode: host",
        });
      }
    }
    return findings;
  },
};
