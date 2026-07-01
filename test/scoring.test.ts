import { describe, it, expect } from "vitest";
import { ctxFromCompose } from "./helpers";
import { buildReport } from "../src/core/scanner";
import { scoreActiveFindings } from "../src/core/score";
import type { Finding } from "../src/core/model";

const STAMP = { generatedAt: "2026-07-01T00:00:00.000Z" };

const cleanStack =
  `services:\n  app:\n    image: nginx:1.27\n    restart: unless-stopped\n    user: "1000:1000"\n` +
  `    healthcheck:\n      test: ["CMD", "true"]\n    labels:\n      app: demo\n` +
  `    deploy:\n      resources:\n        limits:\n          memory: 128M\n` +
  `    ports:\n      - "127.0.0.1:8080:80"\n`;

describe("capped-bucket scoring", () => {
  it("acceptance: a clean stack still scores >= 90", () => {
    const report = buildReport(ctxFromCompose(cleanStack), STAMP);
    expect(report.summary.riskScore).toBeGreaterThanOrEqual(90);
  });

  it("acceptance: one public database scores clearly risky", () => {
    const report = buildReport(
      ctxFromCompose(`services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n`),
      STAMP,
    );
    expect(report.summary.riskScore).toBeLessThanOrEqual(60);
  });

  it("acceptance: 25 unpinned images (no active high) stays above 80", () => {
    let yaml = "services:\n";
    for (let i = 0; i < 25; i++) {
      yaml += `  svc${i}:\n    image: registry.example.com/app${i}:1.0\n`;
    }
    const report = buildReport(ctxFromCompose(yaml), STAMP);
    expect(report.summary.active.high).toBe(0);
    expect(report.summary.riskScore).toBeGreaterThan(80);
  });

  it("caps each bucket: ten unpinned images cost the same as five", () => {
    const mk = (ruleId: string): Finding => ({
      ruleId,
      severity: "low",
      title: "x",
      detail: "x",
      classification: "active",
    });
    const ten = scoreActiveFindings(Array.from({ length: 10 }, () => mk("unpinned-image")));
    const five = scoreActiveFindings(Array.from({ length: 5 }, () => mk("unpinned-image")));
    expect(ten.score).toBe(five.score); // imagePinning capped at 5
    expect(ten.score).toBe(95);
  });

  it("excludes conditional and template findings from the score", () => {
    const active: Finding = { ruleId: "database-port-exposed", severity: "high", title: "x", detail: "x", classification: "active" };
    const conditional: Finding = { ...active, classification: "conditional" };
    const template: Finding = { ...active, classification: "template" };
    expect(scoreActiveFindings([conditional, template]).score).toBe(100);
    expect(scoreActiveFindings([active]).score).toBe(60);
  });
});
