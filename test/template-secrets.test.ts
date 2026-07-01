import { describe, it, expect } from "vitest";
import { buildReport } from "../src/core/scanner";
import { isEnvTemplateFile } from "../src/core/classify";
import type { EnvEntry, ScanContext } from "../src/core/model";

const STAMP = { generatedAt: "2026-07-01T00:00:00.000Z" };

function ctxWithEnvFile(path: string, entries: EnvEntry[]): ScanContext {
  return { target: "t", files: [path], services: [], envFiles: [{ path, entries }], tunnels: [] };
}

const difyDefault: EnvEntry[] = [{ key: "DB_PASSWORD", value: "difyai123456", isReference: false }];

describe("isEnvTemplateFile", () => {
  it("treats example/sample/template names and files under examples/ as templates", () => {
    for (const p of ["stack/.env.example", "a/.env.sample", "b/.env.template", "examples/x/.env"]) {
      expect(isEnvTemplateFile(p)).toBe(true);
    }
  });
  it("treats real env files as active", () => {
    for (const p of ["stack/.env", "stack/.env.local", "stack/.env.production", "stack/.env.prod"]) {
      expect(isEnvTemplateFile(p)).toBe(false);
    }
  });
});

describe("template vs active env secret severity", () => {
  it("acceptance: .env.example with DB_PASSWORD=difyai123456 is NOT high (template, info)", () => {
    const report = buildReport(ctxWithEnvFile("stack/.env.example", difyDefault), STAMP);
    const f = report.findings.find((x) => x.ruleId === "plaintext-secret");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("info");
    expect(f!.classification).toBe("template");
    expect(report.summary.active.high).toBe(0);
    expect(report.summary.template.total).toBeGreaterThan(0);
  });

  it("acceptance: .env with DB_PASSWORD=difyai123456 stays HIGH and active", () => {
    const report = buildReport(ctxWithEnvFile("stack/.env", difyDefault), STAMP);
    const f = report.findings.find((x) => x.ruleId === "plaintext-secret");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("high");
    expect(f!.classification).toBe("active");
    expect(report.summary.active.high).toBeGreaterThan(0);
  });

  it("never leaks the secret value, even for template findings", () => {
    for (const path of ["stack/.env", "stack/.env.example"]) {
      const json = JSON.stringify(buildReport(ctxWithEnvFile(path, difyDefault), STAMP));
      expect(json).not.toContain("difyai123456");
    }
  });
});
