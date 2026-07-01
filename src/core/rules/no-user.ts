import type { Finding, Rule } from "../model";
import { isPublicPort } from "./util";

export const rule: Rule = {
  id: "no-user",
  description:
    "Flags exposed services that do not set an explicit non-root user.",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      if (service.user !== undefined && service.user !== "") {
        continue;
      }
      const hasPublicPort = service.ports.some((port) => isPublicPort(port));
      if (!hasPublicPort) {
        continue;
      }
      findings.push({
        ruleId: rule.id,
        severity: "info",
        title: `Does not set a user (defaults to root)`,
        service: service.name,
        file: service.file,
        detail:
          `Exposed service "${service.name}" sets no "user:", so it likely runs as the image's default user (often root).`,
        recommendation:
          "Set a non-root `user:` (e.g. `user: \"1000:1000\"`) for services reachable from the network.",
      });
    }
    return findings;
  },
};
