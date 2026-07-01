import type { Finding, Rule } from "../model";
import { detectServiceType } from "../services";

export const rule: Rule = {
  id: "cloudflared-no-access",
  description:
    "Flags Cloudflare Tunnels with no Access policy, or a cloudflared service with no ingress config.",
  run(ctx) {
    const findings: Finding[] = [];

    for (const tunnel of ctx.tunnels) {
      if (tunnel.hasAccessHint === false) {
        findings.push({
          ruleId: rule.id,
          severity: "medium",
          title: "Cloudflare Tunnel has no Access policy",
          file: tunnel.file,
          detail:
            "This Cloudflare Tunnel exposes services publicly but shows no sign of a Cloudflare Access policy, so anyone who knows the hostname can reach the origin.",
          recommendation:
            "Add a Cloudflare Access policy (e.g. email / IdP / MFA) in front of the tunneled hostnames.",
        });
      }
    }

    if (ctx.tunnels.length === 0) {
      const cloudflaredService = ctx.services.find((service) => {
        const def = detectServiceType(service);
        return def?.category === "tunnel";
      });
      if (cloudflaredService) {
        findings.push({
          ruleId: rule.id,
          severity: "medium",
          title: "cloudflared present but no ingress/Access config found",
          service: cloudflaredService.name,
          file: cloudflaredService.file,
          detail:
            "A cloudflared (Cloudflare Tunnel) service is present but no ingress or Access configuration was found, so its protection cannot be verified.",
          recommendation:
            "Add a Cloudflare Access policy (e.g. email / IdP / MFA) in front of the tunneled hostnames.",
        });
      }
    }

    return findings;
  },
};
