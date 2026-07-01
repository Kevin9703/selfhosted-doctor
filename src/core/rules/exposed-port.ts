import type { Finding, Rule, Severity } from "../model";
import { detectServiceType, isDatabaseService } from "../services";
import { formatPort, isPublicPort } from "./util";

export const rule: Rule = {
  id: "exposed-port",
  description:
    "Flags services that publish ports on a public host interface (databases are handled separately).",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      // Database exposure is covered by the database-port-exposed rule.
      if (isDatabaseService(service)) {
        continue;
      }
      const def = detectServiceType(service);
      const isIngress = def?.category === "proxy" || def?.category === "tunnel";
      for (const port of service.ports) {
        if (!isPublicPort(port)) {
          continue;
        }
        let severity: Severity = "high";
        if (
          isIngress &&
          (port.containerPort === "80" || port.containerPort === "443")
        ) {
          // Expected ingress for a reverse proxy / tunnel.
          severity = "medium";
        }
        findings.push({
          ruleId: rule.id,
          severity,
          title: `Publishes port ${port.containerPort} to the public`,
          service: service.name,
          file: service.file,
          detail:
            `Service "${service.name}" publishes container port ${port.containerPort} on a public host interface, making it reachable from any network the host is on.`,
          recommendation:
            "Bind the port to 127.0.0.1 (e.g. 127.0.0.1:PORT:PORT) or place the service behind a reverse proxy / tunnel that enforces authentication.",
          evidence: formatPort(port),
        });
      }
    }
    return findings;
  },
};
