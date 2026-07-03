import { describe, it, expect } from "vitest";
import { ctxFromCompose, FIXTURE_SECRETS } from "./helpers";
import { buildReport, scan } from "../src/core/scanner";
import { assessExposure, decideVerdict, labelFromPath } from "../src/core/verdict";
import { renderExpose } from "../src/report/expose";
import type { ExposeItem } from "../src/core/verdict";
import type { EnvEntry, ScanContext } from "../src/core/model";

/** All fixes (single or grouped) for a blocker as one string, for matching. */
function fixText(item: ExposeItem): string {
  return item.fixes && item.fixes.length > 0 ? item.fixes.join(" || ") : (item.fix ?? "");
}

const STAMP = { generatedAt: "2026-07-01T00:00:00.000Z" };

/** Assess an inline compose string with no filesystem. */
function assess(yaml: string, target = "test/my-stack") {
  const report = buildReport(ctxFromCompose(yaml), STAMP);
  report.target = target;
  return assessExposure(report);
}

const ruleIds = (items: ExposeItem[]): string[] => items.map((i) => i.ruleId);

describe("decideVerdict precedence", () => {
  const blocker: ExposeItem = { kind: "blocker", ruleId: "x", headline: "x" };
  const access: ExposeItem = { kind: "access", ruleId: "y", headline: "y" };

  it("any blocker wins → dont-expose", () => {
    expect(
      decideVerdict({ blockers: [blocker], access: [access], unresolvedPorts: [{ service: "a", raw: "b" }], entryPoints: [] }),
    ).toBe("dont-expose");
  });

  it("unresolved port (no blocker) → check-manually, ahead of access", () => {
    expect(
      decideVerdict({ blockers: [], access: [access], unresolvedPorts: [{ service: "a", raw: "b" }], entryPoints: [] }),
    ).toBe("check-manually");
  });

  it("public surface needing access (no blocker/unresolved) → behind-access", () => {
    expect(decideVerdict({ blockers: [], access: [access], unresolvedPorts: [], entryPoints: [] })).toBe("behind-access");
  });

  it("nothing to act on → looks-ok", () => {
    expect(decideVerdict({ blockers: [], access: [], unresolvedPorts: [], entryPoints: [] })).toBe("looks-ok");
  });
});

describe("assessExposure — blockers vs. secondary", () => {
  it("a public database port is a blocker → DON'T EXPOSE YET", () => {
    const a = assess(`services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n`);
    expect(a.verdict).toBe("dont-expose");
    expect(ruleIds(a.blockers)).toContain("database-port-exposed");
    expect(a.entryPoints.map((e) => e.service)).toContain("db");
    // The concrete fix binds to loopback.
    expect(a.blockers[0]?.fix).toContain("127.0.0.1:5432:5432");
  });

  it("a raw app/debug port published to 0.0.0.0 is a blocker", () => {
    const a = assess(`services:\n  debugger:\n    image: myapp:1.0\n    ports:\n      - "5003:5003"\n`);
    expect(a.verdict).toBe("dont-expose");
    expect(ruleIds(a.blockers)).toContain("exposed-port");
    expect(a.blockers[0]?.fix).toContain(`"5003:5003"  →  "127.0.0.1:5003:5003"`);
  });

  it("internal ${VAR:-default} secrets are NOT blockers on their own → LOOKS OK", () => {
    const a = assess(
      `services:\n  app:\n    image: myapp:1.0\n    environment:\n      POSTGRES_PASSWORD: \${DB_PASSWORD:-difyai123456}\n`,
    );
    expect(a.blockers).toHaveLength(0);
    expect(a.verdict).toBe("looks-ok");
    expect(ruleIds(a.changeBeforePublic)).toContain("default-secret-fallback");
    // Framed as "fine on private", never dumped as a blocker.
    expect(a.changeBeforePublic[0]?.why).toMatch(/private network/i);
  });

  it("a public db port + an internal default secret: port blocks, secret is demoted (not a blocker)", () => {
    const a = assess(
      `services:\n` +
        `  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n` +
        `  app:\n    image: myapp:1.0\n    environment:\n      POSTGRES_PASSWORD: \${DB_PASSWORD:-difyai123456}\n`,
    );
    expect(a.verdict).toBe("dont-expose");
    expect(ruleIds(a.blockers)).toContain("database-port-exposed");
    // The default-secret fallback must NOT be a top blocker.
    expect(ruleIds(a.blockers)).not.toContain("default-secret-fallback");
    expect(a.changeBeforePublic).toHaveLength(1);
  });

  it("a real plaintext secret in the deployed compose is a blocker", () => {
    const a = assess(
      `services:\n  app:\n    image: myapp:1.0\n    environment:\n      ADMIN_TOKEN: hardcoded-super-secret-value\n`,
    );
    expect(a.verdict).toBe("dont-expose");
    expect(ruleIds(a.blockers)).toContain("plaintext-secret");
  });
});

describe("assessExposure — reverse-proxy front doors & access", () => {
  it("a reverse proxy on 80/443 is a front door, not a blocker → EXPOSE ONLY BEHIND ACCESS", () => {
    const a = assess(`services:\n  nginx:\n    image: nginx:1.27\n    ports:\n      - "80:80"\n      - "443:443"\n`);
    expect(a.verdict).toBe("behind-access");
    expect(a.blockers).toHaveLength(0);
    expect(ruleIds(a.access)).toContain("exposed-port");
    // 80 and 443 collapse to one grouped front-door item.
    const front = a.access.find((i) => i.ruleId === "exposed-port");
    expect(front?.headline).toMatch(/80\/443/);
    expect(a.access.filter((i) => i.ruleId === "exposed-port")).toHaveLength(1);
  });

  it("a loopback-only stack is not internet-reachable → LOOKS OK, no entry points", () => {
    const a = assess(`services:\n  app:\n    image: nginx:1.27\n    ports:\n      - "127.0.0.1:8080:80"\n`);
    expect(a.verdict).toBe("looks-ok");
    expect(a.entryPoints).toHaveLength(0);
    expect(a.blockers).toHaveLength(0);
  });

  it("a front-door proxy with a dynamic host port it can't resolve → CHECK MANUALLY", () => {
    const a = assess(`services:\n  nginx:\n    image: nginx:1.27\n    ports:\n      - "\${NGINX_PORT}:80"\n`);
    expect(a.verdict).toBe("check-manually");
    expect(a.unresolvedPorts.length).toBeGreaterThan(0);
  });
});

describe("assessExposure — hygiene & conditional", () => {
  it("collapses hygiene to a count and never enumerates it as items", () => {
    let yaml = "services:\n";
    for (let i = 0; i < 6; i++) yaml += `  svc${i}:\n    image: registry.example.com/app${i}:1.0\n`;
    const a = assess(yaml);
    expect(a.hygieneCount).toBeGreaterThan(0);
    expect(a.blockers).toHaveLength(0);
    expect(a.access).toHaveLength(0);
  });

  it("counts profile-gated risks as a conditional note, not part of the verdict", () => {
    const report = scan("test/fixtures/dify-like", { ...STAMP, allProfiles: false });
    const a = assessExposure(report);
    // Default (active) surface is intentionally loopback-only + internal defaults.
    expect(a.blockers).toHaveLength(0);
    expect(a.verdict).toBe("looks-ok");
    // Internal default secrets are demoted, not blockers.
    expect(a.changeBeforePublic.length).toBeGreaterThan(0);
    // The scary public databases / privileged live behind profiles.
    expect(a.conditionalHigh).toBeGreaterThan(0);
    expect(a.conditionalProfiles).toContain("vastbase");
  });
});

describe("assessExposure — blocker grouping, cap & wording", () => {
  it("collapses several host-control blockers on one service into a single item", () => {
    const a = assess(
      `services:\n  watchtower:\n    image: containrrr/watchtower:latest\n    privileged: true\n` +
        `    network_mode: host\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n`,
    );
    expect(a.verdict).toBe("dont-expose");
    // Docker socket + host network + privileged → ONE decision, not three.
    expect(a.blockers).toHaveLength(1);
    const b = a.blockers[0]!;
    expect(b.headline).toMatch(/effectively has root on the host/i);
    expect(b.fixes?.length).toBe(3);
  });

  it("never doubles the word 'database' for a service literally named 'database'", () => {
    const a = assess(`services:\n  database:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n`);
    expect(a.blockers).toHaveLength(1);
    expect(a.blockers[0]?.headline).not.toMatch(/database database/i);
    expect(a.blockers[0]?.headline).toBe("database publishes database port 5432 to 0.0.0.0");
  });

  it("caps the blocker list at 4 and reports the rest as overflow, DBs ranked first", () => {
    let yaml = "services:\n";
    for (let i = 0; i < 6; i++) yaml += `  db${i}:\n    image: postgres:16\n    ports:\n      - "54${i}0:5432"\n`;
    const a = assess(yaml);
    expect(a.blockers).toHaveLength(4);
    expect(a.blockerOverflow).toBe(2);
    // All six are databases, so every shown blocker is a database line.
    expect(a.blockers.every((b) => b.headline.includes("database port"))).toBe(true);
  });

  it("excludes missing-labels / missing-resource-limits from the hygiene count", () => {
    const yaml = `services:\n  app:\n    image: myapp:1.0\n`;
    const report = buildReport(ctxFromCompose(yaml), STAMP);
    const a = assessExposure(report);
    const kept = new Set(["missing-healthcheck", "missing-restart", "runs-as-root", "no-user", "latest-tag", "unpinned-image"]);
    const expected = report.findings.filter((f) => (f.classification ?? "active") === "active" && kept.has(f.ruleId)).length;
    const excluded = report.findings.filter(
      (f) => f.ruleId === "missing-labels" || f.ruleId === "missing-resource-limits",
    ).length;
    expect(excluded).toBeGreaterThan(0); // they exist in the report...
    expect(a.hygieneCount).toBe(expected); // ...but are not in the count.
  });
});

describe("assessExposure — many-secrets / many-ports summarization (no run-on)", () => {
  it("summarizes many secrets on one service into one deduped clause", () => {
    const a = assess(
      `services:\n  app:\n    image: myapp:1.0\n    environment:\n` +
        `      API_TOKEN: realsecretvalue123\n      DB_PASSWORD: anothersecretvalue\n` +
        `      AUTH_SECRET: yetanothersecret1\n      SMTP_PASS: smtppasswordvalue9\n      ACCESS_KEY: accesskeyvalue99\n`,
    );
    expect(a.blockers).toHaveLength(1);
    const h = a.blockers[0]!.headline;
    expect(h).toMatch(/hardcodes 5 real secrets/);
    expect(h).toContain("+2 more"); // names at most 3, then "+N more"
    // The phrase must appear once — never repeated per key (the old run-on bug).
    expect((h.match(/hardcodes/g) ?? []).length).toBe(1);
  });

  it("summarizes many ports on one service into one clause with a bind-each fix", () => {
    const a = assess(
      `services:\n  app:\n    image: myapp:1.0\n    ports:\n` +
        `      - "3000:3000"\n      - "3001:3001"\n      - "3002:3002"\n      - "3003:3003"\n      - "3004:3004"\n`,
    );
    expect(a.blockers).toHaveLength(1);
    const h = a.blockers[0]!.headline;
    expect(h).toMatch(/publishes 5 ports/);
    expect(h).toContain("+1 more");
    expect((h.match(/publishes/g) ?? []).length).toBe(1);
    expect(fixText(a.blockers[0]!)).toMatch(/bind each published port/);
  });

  it("renders an unresolved ${VAR} port honestly, not as a confident reachable port", () => {
    const a = assess(`services:\n  app:\n    image: myapp:1.0\n    ports:\n      - "\${APP_PORT}:8080"\n`);
    expect(a.verdict).toBe("dont-expose");
    const h = a.blockers[0]!.headline;
    expect(h).toMatch(/variable port/);
    expect(h).toContain("unresolved");
    expect(h).toContain("${APP_PORT}");
    // Not asserted as a resolved reachable port in the entry-point list.
    expect(a.entryPoints[0]?.ports).toHaveLength(0);
    expect(a.entryPoints[0]?.variablePorts).toContain("${APP_PORT}");
  });

  it("labels file-level env secrets by file (never an empty service), deduping keys across files", () => {
    const secretEnv = (path: string, keys: string[]) => ({
      path,
      entries: keys.map((key): EnvEntry => ({ key, value: "realsecretvalue123", isReference: false })),
    });
    const ctx: ScanContext = {
      target: "test/stack",
      files: [".env", ".env.local"],
      services: [],
      envFiles: [secretEnv(".env", ["API_TOKEN", "DB_PASSWORD"]), secretEnv(".env.local", ["API_TOKEN", "S3_ACCESS_KEY"])],
      tunnels: [],
    };
    const a = assessExposure(buildReport(ctx, STAMP));
    expect(a.blockers).toHaveLength(1);
    const h = a.blockers[0]!.headline;
    expect(h.startsWith(" ")).toBe(false); // no empty service-label prefix
    expect(h).toMatch(/env file/i);
    expect(h).toMatch(/3 real secrets/); // API_TOKEN deduped across the two files
    expect((h.match(/API_TOKEN/g) ?? []).length).toBe(1);
  });
});

describe("assessExposure — real vaultwarden example", () => {
  const report = scan("examples/vaultwarden-cloudflare", STAMP);
  const a = assessExposure(report);

  it("the real ADMIN_TOKEN secret + published port drive DON'T EXPOSE YET, grouped into one vaultwarden item", () => {
    expect(a.verdict).toBe("dont-expose");
    // Both blockers live on the same service → one item carrying both facts + fixes.
    expect(a.blockers).toHaveLength(1);
    const b = a.blockers[0]!;
    expect(b.headline).toContain("ADMIN_TOKEN");
    expect(b.headline).toContain("8080");
    expect(b.fixes?.some((f) => f.includes("127.0.0.1:8080:80"))).toBe(true);
  });

  it("labels the stack Vaultwarden and collapses the two tunnel items into one", () => {
    expect(a.stackLabel).toBe("Vaultwarden");
    expect(a.hasTunnel).toBe(true);
    // The specific "routes to a sensitive service" line wins; the generic
    // "no Access policy" line is deduped away.
    expect(ruleIds(a.access)).toContain("cloudflared-tunnel-to-risky");
    expect(ruleIds(a.access)).not.toContain("cloudflared-no-access");
  });

  it("renders without leaking any secret value", () => {
    const out = renderExpose(a, { color: false });
    expect(out).toContain("DON'T EXPOSE YET");
    for (const secret of FIXTURE_SECRETS) expect(out).not.toContain(secret);
  });
});

describe("labelFromPath", () => {
  it("skips generic dir/file names and capitalizes the meaningful segment", () => {
    expect(labelFromPath("/home/me/dify/docker/docker-compose.yaml")).toBe("Dify");
    expect(labelFromPath("immich/docker-compose.yml")).toBe("Immich");
    expect(labelFromPath("docker-compose.yaml")).toBe("This stack");
  });
});
