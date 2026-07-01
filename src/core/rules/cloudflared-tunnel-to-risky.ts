import type { Finding, Rule } from "../model";
import { detectServiceType } from "../services";

const SENSITIVE_KEYWORDS = ["vaultwarden", "bitwarden"];

export const rule: Rule = {
  id: "cloudflared-tunnel-to-risky",
  description:
    "Flags unprotected Cloudflare Tunnels that route to sensitive services.",
  run(ctx) {
    const findings: Finding[] = [];

    // Names of services whose detected definition is marked sensitive.
    const sensitiveServiceNames: string[] = [];
    for (const service of ctx.services) {
      const def = detectServiceType(service);
      if (def?.sensitive) {
        sensitiveServiceNames.push(service.name.toLowerCase());
      }
    }

    for (const tunnel of ctx.tunnels) {
      if (tunnel.hasAccessHint !== false) {
        continue;
      }
      let matched = false;
      for (const ingress of tunnel.ingress) {
        const haystacks: string[] = [];
        if (ingress.hostname) {
          haystacks.push(ingress.hostname.toLowerCase());
        }
        if (ingress.service) {
          haystacks.push(ingress.service.toLowerCase());
        }
        for (const hay of haystacks) {
          if (SENSITIVE_KEYWORDS.some((keyword) => hay.includes(keyword))) {
            matched = true;
            break;
          }
          if (sensitiveServiceNames.some((name) => name !== "" && hay.includes(name))) {
            matched = true;
            break;
          }
        }
        if (matched) {
          break;
        }
      }
      if (matched) {
        findings.push({
          ruleId: rule.id,
          severity: "high",
          title: "Cloudflare Tunnel routes to a sensitive service without Access",
          file: tunnel.file,
          detail:
            "A Cloudflare Tunnel with no Access policy routes to a sensitive application (such as a password manager), exposing it to anyone who learns the hostname.",
          recommendation:
            "Protect sensitive apps with a Cloudflare Access policy and MFA before tunneling them to the public internet.",
        });
      }
    }

    return findings;
  },
};
