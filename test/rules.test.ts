import { describe, it, expect } from "vitest";
import { ctxFromCompose } from "./helpers";
import { RULES, runRules } from "../src/core/rules";
import { rule as serviceNotes } from "../src/core/rules/service-notes";
import type { Finding, Rule, ScanContext } from "../src/core/model";

import { rule as exposedPort } from "../src/core/rules/exposed-port";
import { rule as privileged } from "../src/core/rules/privileged";
import { rule as hostNetwork } from "../src/core/rules/host-network";
import { rule as dockerSocket } from "../src/core/rules/docker-socket";
import { rule as dbPort } from "../src/core/rules/database-port-exposed";
import { rule as plaintextSecret } from "../src/core/rules/plaintext-secret";
import { rule as latestTag } from "../src/core/rules/latest-tag";
import { rule as runsAsRoot } from "../src/core/rules/runs-as-root";
import { rule as cloudflaredNoAccess } from "../src/core/rules/cloudflared-no-access";
import { rule as cloudflaredRisky } from "../src/core/rules/cloudflared-tunnel-to-risky";

const idsOf = (fs: Finding[]) => fs.map((f) => f.ruleId);

describe("rule registry", () => {
  it("registers at least 15 rules with unique ids", () => {
    expect(RULES.length).toBeGreaterThanOrEqual(15);
    expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length);
  });
});

describe("high-severity rules", () => {
  it("exposed-port flags a public bind but not a loopback bind", () => {
    const pub = exposedPort.run(ctxFromCompose(`services:\n  web:\n    image: app:1\n    ports:\n      - "8080:80"\n`));
    expect(pub).toHaveLength(1);
    expect(pub[0]).toMatchObject({ severity: "high", service: "web" });

    const loop = exposedPort.run(ctxFromCompose(`services:\n  web:\n    image: app:1\n    ports:\n      - "127.0.0.1:8080:80"\n`));
    expect(loop).toHaveLength(0);
  });

  it("exposed-port skips databases (covered by database-port-exposed)", () => {
    const ctx = ctxFromCompose(`services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n`);
    expect(exposedPort.run(ctx)).toHaveLength(0);
    expect(dbPort.run(ctx)).toHaveLength(1);
    expect(dbPort.run(ctx)[0]).toMatchObject({ severity: "high" });
  });

  it("exposed-port downgrades proxy 80/443 to medium", () => {
    const f = exposedPort.run(ctxFromCompose(`services:\n  proxy:\n    image: traefik:v3.0\n    ports:\n      - "443:443"\n`));
    expect(f[0]).toMatchObject({ severity: "medium" });
  });

  it("exposed-port uses Compose default ports when downgrading proxy ingress", () => {
    const f = exposedPort.run(
      ctxFromCompose(
        `services:\n  proxy:\n    image: nginx:1.27\n    ports:\n      - "\${HOST_HTTP:-80}:\${NGINX_PORT:-80}"\n`,
      ),
    );
    expect(f[0]).toMatchObject({ severity: "medium", title: "Publishes port 80 to the public" });
    expect(f[0]?.evidence).toContain("${HOST_HTTP:-80}");
  });

  it("privileged / host-network / docker-socket fire", () => {
    expect(privileged.run(ctxFromCompose(`services:\n  a:\n    image: x\n    privileged: true\n`))).toHaveLength(1);
    expect(hostNetwork.run(ctxFromCompose(`services:\n  a:\n    image: x\n    network_mode: host\n`))).toHaveLength(1);
    expect(
      dockerSocket.run(ctxFromCompose(`services:\n  a:\n    image: x\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock:ro\n`)),
    ).toHaveLength(1);
  });

  it("plaintext-secret flags a literal but ignores a ${VAR} reference", () => {
    const flagged = plaintextSecret.run(
      ctxFromCompose(`services:\n  a:\n    image: x\n    environment:\n      ADMIN_TOKEN: hunter2hunter2\n`),
    );
    expect(flagged).toHaveLength(1);
    expect(flagged[0]!.evidence).not.toContain("hunter2hunter2");

    const ref = plaintextSecret.run(
      ctxFromCompose(`services:\n  a:\n    image: x\n    environment:\n      ADMIN_TOKEN: \${ADMIN_TOKEN}\n`),
    );
    expect(ref).toHaveLength(0);
  });
});

describe("hygiene rules", () => {
  it("latest-tag fires on :latest and implicit latest, not on a pinned tag", () => {
    expect(latestTag.run(ctxFromCompose(`services:\n  a:\n    image: nginx:latest\n`))).toHaveLength(1);
    expect(latestTag.run(ctxFromCompose(`services:\n  a:\n    image: nginx\n`))).toHaveLength(1);
    expect(latestTag.run(ctxFromCompose(`services:\n  a:\n    image: nginx:1.27\n`))).toHaveLength(0);
  });

  it("runs-as-root fires only on explicit root/0", () => {
    expect(runsAsRoot.run(ctxFromCompose(`services:\n  a:\n    image: x\n    user: "0:0"\n`))).toHaveLength(1);
    expect(runsAsRoot.run(ctxFromCompose(`services:\n  a:\n    image: x\n    user: "1000"\n`))).toHaveLength(0);
  });
});

describe("cloudflare rules", () => {
  const tunnelCtx = (hasAccessHint: boolean): ScanContext => ({
    target: "t",
    files: ["cloudflared/config.yml"],
    services: [],
    envFiles: [],
    tunnels: [
      {
        file: "cloudflared/config.yml",
        hasAccessHint,
        ingress: [{ hostname: "vault.example.com", service: "http://vaultwarden:80" }],
      },
    ],
  });

  it("flags a tunnel with no Access policy", () => {
    expect(idsOf(cloudflaredNoAccess.run(tunnelCtx(false)))).toContain("cloudflared-no-access");
    expect(cloudflaredNoAccess.run(tunnelCtx(true))).toHaveLength(0);
  });

  it("flags a tunnel to a sensitive service (high)", () => {
    const f = cloudflaredRisky.run(tunnelCtx(false));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "high" });
    expect(cloudflaredRisky.run(tunnelCtx(true))).toHaveLength(0);
  });
});

describe("runRules", () => {
  it("sorts findings high-first", () => {
    const ctx = ctxFromCompose(
      `services:\n  web:\n    image: app:latest\n    ports:\n      - "8080:80"\n`,
    );
    const findings = runRules(ctx);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0]!.severity).toBe("high");
  });

  it("surfaces a failing rule as a visible rule-error finding instead of swallowing it", () => {
    const boom: Rule = {
      id: "boom",
      description: "always throws",
      run() {
        throw new Error("kaboom");
      },
    };
    const ctx = ctxFromCompose(`services:\n  a:\n    image: x:1\n`);
    const findings = runRules(ctx, [boom]);
    const err = findings.find((f) => f.ruleId === "rule-error");
    expect(err).toBeDefined();
    expect(err!.severity).toBe("info");
    expect(err!.title).toContain("boom");
    expect(err!.detail).toContain("kaboom");
  });
});

describe("service-notes deduplication", () => {
  // Two immich containers + an exposed database. The db-exposed and "back up"
  // notes are about the APP and must fire once, on the public-facing service.
  const immichCtx = ctxFromCompose(
    `services:\n` +
      `  immich-server:\n    image: ghcr.io/immich-app/immich-server:release\n    ports:\n      - "2283:2283"\n` +
      `  immich-machine-learning:\n    image: ghcr.io/immich-app/immich-machine-learning:release\n` +
      `  database:\n    image: tensorchord/pgvecto-rs:pg14\n    ports:\n      - "5432:5432"\n`,
  );

  it("emits the db-exposed note once, attached to the main app service", () => {
    const notes = serviceNotes.run(immichCtx);
    const dbExposed = notes.filter((f) => f.severity === "high" && /database is exposed/i.test(f.title));
    expect(dbExposed).toHaveLength(1);
    expect(dbExposed[0]!.service).toBe("immich-server");
  });

  it("never attaches an immich note to the machine-learning sidecar", () => {
    const notes = serviceNotes.run(immichCtx);
    expect(notes.some((f) => f.service === "immich-machine-learning")).toBe(false);
  });

  it("emits each immich note at most once", () => {
    const notes = serviceNotes.run(immichCtx);
    const titles = notes.map((f) => f.title);
    expect(new Set(titles).size).toBe(titles.length);
  });
});
