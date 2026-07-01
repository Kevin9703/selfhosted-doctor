import type { Finding, Rule } from "../model";

const ROOT_USERS = new Set(["root", "0", "0:0"]);

export const rule: Rule = {
  id: "runs-as-root",
  description: "Flags services explicitly configured to run as root.",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      const user = service.user;
      if (user !== undefined && ROOT_USERS.has(user.trim())) {
        findings.push({
          ruleId: rule.id,
          severity: "medium",
          title: `Runs as the root user`,
          service: service.name,
          file: service.file,
          detail:
            `Service "${service.name}" is explicitly configured to run as root ("user: ${user}"). A compromise of the process then has root inside the container.`,
          recommendation:
            "Run the service as a non-root user (e.g. `user: \"1000:1000\"`).",
          evidence: `user: ${user}`,
        });
      }
    }
    return findings;
  },
};
