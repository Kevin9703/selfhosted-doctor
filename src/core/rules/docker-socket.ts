import type { Finding, Rule } from "../model";

const SOCKET_PATH = "/var/run/docker.sock";

export const rule: Rule = {
  id: "docker-socket",
  description: "Flags services that mount the Docker socket.",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      for (const volume of service.volumes) {
        const source = volume.source;
        if (source === undefined) {
          continue;
        }
        const mountsSocket =
          source === SOCKET_PATH ||
          source.endsWith(SOCKET_PATH) ||
          source.includes("docker.sock");
        if (!mountsSocket) {
          continue;
        }
        const readOnlyNote = volume.readOnly
          ? " Mounting it read-only (:ro) reduces but does not remove the risk."
          : "";
        findings.push({
          ruleId: rule.id,
          severity: "high",
          title: `Mounts the Docker socket`,
          service: service.name,
          file: service.file,
          detail:
            `Service "${service.name}" mounts the Docker socket. Access to the Docker socket is equivalent to root on the host, since it can start privileged containers.${readOnlyNote}`,
          recommendation:
            "Use a Docker socket proxy that grants only the specific, least-privilege API calls the service needs instead of mounting the raw socket.",
          evidence: volume.readOnly ? `${SOCKET_PATH} (read-only)` : SOCKET_PATH,
        });
      }
    }
    return findings;
  },
};
