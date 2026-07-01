import { describe, it, expect } from "vitest";
import { scan } from "../src/core/scanner";
import { renderReport } from "../src/report";
import { explainReport } from "../src/ai/explain";

const STAMP = { generatedAt: "2026-07-01T00:00:00.000Z" };
const DIFY = "test/fixtures/dify-like";

// Secret-looking values planted in the fixture; none may appear in any output.
const DIFY_SECRETS = ["difyai123456", "Vastbase@123", "Enmo@123", "sk-difyai123456placeholder"];

describe("Dify-like upstream Compose scan", () => {
  const report = scan(DIFY, STAMP);

  it("acceptance: default scan is NOT 0/100 despite profile-gated services and .env.example", () => {
    expect(report.summary.riskScore).toBeGreaterThan(0);
  });

  it("reports profile-gated services as conditional and template secrets separately", () => {
    expect(report.summary.conditional.total).toBeGreaterThan(0);
    expect(report.summary.template.total).toBeGreaterThan(0);
    // The scary public databases/privileged services are conditional, not active.
    expect(report.findings.some((f) => f.classification === "conditional" && f.severity === "high")).toBe(true);
  });

  it("flags the active ${VAR:-default} fallbacks as high", () => {
    const fallbacks = report.findings.filter(
      (f) => f.ruleId === "default-secret-fallback" && f.classification === "active",
    );
    expect(fallbacks.length).toBeGreaterThan(0);
    expect(fallbacks.every((f) => f.severity === "high")).toBe(true);
  });

  it("lowers the score when all profiles are enabled", () => {
    const all = scan(DIFY, { ...STAMP, allProfiles: true });
    expect(all.summary.riskScore).toBeLessThan(report.summary.riskScore);
  });

  it("renders Conditional Findings and Template Findings sections in Markdown", () => {
    const md = renderReport(report, "markdown");
    expect(md).toContain("## Conditional Findings");
    expect(md).toContain("## Template Findings");
    // conditional findings note the gating profile
    expect(md).toMatch(/only when profile `?(milvus|vastbase|opengauss)/);
  });

  it("never leaks a secret value across terminal / json / markdown / explain", () => {
    const outputs = [
      renderReport(report, "terminal", { color: false }),
      renderReport(report, "json"),
      renderReport(report, "markdown"),
      explainReport(report),
    ];
    for (const out of outputs) {
      for (const secret of DIFY_SECRETS) {
        expect(out).not.toContain(secret);
      }
    }
  });
});
