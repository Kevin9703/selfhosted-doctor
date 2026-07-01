import type { Finding, Rule } from "../model";
import { isDatabaseService } from "../services";
import { effectivePort, formatPort, isPublicPort } from "./util";

export const rule: Rule = {
  id: "database-port-exposed",
  description: "Flags database services that publish ports on a public host interface.",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      if (!isDatabaseService(service)) {
        continue;
      }
      for (const port of service.ports) {
        // Loopback-bound ports are not flagged.
        if (!isPublicPort(port)) {
          continue;
        }
        const containerPort = effectivePort(port.containerPort);
        findings.push({
          ruleId: rule.id,
          severity: "high",
          title: `Database port ${containerPort} is published to the public`,
          service: service.name,
          file: service.file,
          detail:
            `Database service "${service.name}" publishes container port ${containerPort} on a public host interface, giving attackers a direct path to your data.`,
          recommendation:
            "Bind the database to 127.0.0.1 (e.g. 127.0.0.1:PORT:PORT) or keep it on an internal network only with no published host port.",
          evidence: formatPort(port),
        });
      }
    }
    return findings;
  },
};
