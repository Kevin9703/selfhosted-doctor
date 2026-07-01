import { describe, it, expect } from "vitest";
import { scan, buildReport } from "../src/core/scanner";
import { ctxFromCompose, FIXTURE_SECRETS } from "./helpers";
import type { Report } from "../src/core/model";

const STAMP = { generatedAt: "2026-07-01T00:00:00.000Z" };

function ruleIds(report: Report): Set<string> {
  return new Set(report.findings.map((f) => f.ruleId));
}

describe("scan() end-to-end on example stacks", () => {
  it("vaultwarden + cloudflare: exposure, secrets, tunnel risks", () => {
    const report = scan("examples/vaultwarden-cloudflare", STAMP);
    const ids = ruleIds(report);
    expect(ids).toContain("exposed-port");
    expect(ids).toContain("plaintext-secret");
    expect(ids).toContain("cloudflared-no-access");
    expect(ids).toContain("cloudflared-tunnel-to-risky");
    expect(ids).toContain("service-notes"); // vaultwarden exposed note
    expect(report.summary.counts.high).toBeGreaterThan(0);
    expect(report.exposure.some((e) => e.service === "vaultwarden")).toBe(true);
  });

  it("immich + postgres: exposed database is high", () => {
    const report = scan("examples/immich-postgres", STAMP);
    const ids = ruleIds(report);
    expect(ids).toContain("database-port-exposed");
    const dbFinding = report.findings.find((f) => f.ruleId === "database-port-exposed");
    expect(dbFinding?.severity).toBe("high");
    // Immich db-exposed service note should fire (high).
    expect(report.findings.some((f) => f.ruleId === "service-notes" && f.severity === "high")).toBe(true);
  });

  it("nextcloud + db: privileged, host network, docker socket", () => {
    const report = scan("examples/nextcloud-db", STAMP);
    const ids = ruleIds(report);
    expect(ids).toContain("privileged");
    expect(ids).toContain("host-network");
    expect(ids).toContain("docker-socket");
    expect(ids).toContain("database-port-exposed");
    // db mislabeled as nextcloud regression guard: the "db" service is a mariadb.
    const dbSummary = report.services.find((s) => s.name === "db");
    expect(dbSummary?.detectedType).toBe("mariadb");
  });

  it("produces a deterministic, well-formed report shape", () => {
    const report = scan("examples/immich-postgres", STAMP);
    expect(report).toMatchObject({ tool: "selfhosted-doctor", generatedAt: STAMP.generatedAt });
    expect(report.summary.riskScore).toBeGreaterThanOrEqual(0);
    expect(report.summary.riskScore).toBeLessThanOrEqual(100);
    expect(report.summary.counts.total).toBe(report.findings.length);
  });

  it("NEVER leaks a raw secret value into the report JSON", () => {
    for (const dir of ["examples/vaultwarden-cloudflare", "examples/immich-postgres", "examples/nextcloud-db"]) {
      const json = JSON.stringify(scan(dir, STAMP));
      for (const secret of FIXTURE_SECRETS) {
        expect(json).not.toContain(secret);
      }
    }
  });
});

describe("scan() on a clean stack", () => {
  it("scores high and reports no high/medium findings", () => {
    const ctx = ctxFromCompose(
      `services:\n  app:\n    image: nginx:1.27\n    restart: unless-stopped\n    user: "1000:1000"\n    healthcheck:\n      test: ["CMD", "true"]\n    labels:\n      app: demo\n    deploy:\n      resources:\n        limits:\n          memory: 128M\n    ports:\n      - "127.0.0.1:8080:80"\n`,
    );
    const report = buildReport(ctx, STAMP);
    expect(report.summary.counts.high).toBe(0);
    expect(report.summary.counts.medium).toBe(0);
    expect(report.summary.riskScore).toBeGreaterThanOrEqual(90);
  });
});
