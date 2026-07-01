import type { ComposeService, Finding, Rule } from "../model";
import { detectServiceType, isDatabaseService, SERVICE_NOTES } from "../services";
import { isPublicPort } from "./util";

export const rule: Rule = {
  id: "service-notes",
  description:
    "Emits service-specific notes from the catalog based on exposure context.",
  run(ctx) {
    const findings: Finding[] = [];

    const servicePublishesPublicly = (service: ComposeService): boolean =>
      service.ports.some((port) => isPublicPort(port));

    // Whether ANY database service in the stack publishes a public port.
    const anyDbExposed = ctx.services.some(
      (service) =>
        isDatabaseService(service) && servicePublishesPublicly(service),
    );

    // Group services by detected app type. Many stacks run several containers
    // of the same app (e.g. immich-server + immich-machine-learning); a
    // service-level note is about the APP, so we emit it once per type and
    // attach it to the main, public-facing service — never to sidecars/workers.
    const byType = new Map<string, ComposeService[]>();
    for (const service of ctx.services) {
      const def = detectServiceType(service);
      if (!def) continue;
      const group = byType.get(def.id) ?? [];
      group.push(service);
      byType.set(def.id, group);
    }

    for (const note of SERVICE_NOTES) {
      const group = byType.get(note.serviceId);
      if (!group || group.length === 0) continue;

      // The "main" service is the public-facing one if any, else the first.
      const primary = group.find(servicePublishesPublicly) ?? group[0];
      if (!primary) continue;

      let emit = false;
      if (note.when === "always") {
        emit = true;
      } else if (note.when === "exposed") {
        emit = group.some(servicePublishesPublicly);
      } else if (note.when === "db-exposed") {
        emit = anyDbExposed;
      }
      if (!emit) continue;

      findings.push({
        ruleId: rule.id,
        severity: note.severity,
        title: note.title,
        service: primary.name,
        file: primary.file,
        detail: note.detail,
        recommendation: note.recommendation,
      });
    }

    return findings;
  },
};
