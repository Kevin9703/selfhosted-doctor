import { describe, it, expect } from "vitest";
import { scan } from "../src/core/scanner";
import { explainReport } from "../src/ai/explain";
import { FIXTURE_SECRETS } from "./helpers";

const report = scan("examples/vaultwarden-cloudflare", { generatedAt: "2026-07-01T00:00:00.000Z" });

describe("explainReport (mock provider)", () => {
  it("summarizes the deterministic report and highlights high risks", () => {
    const text = explainReport(report, { provider: "mock" });
    expect(text).toContain("Risk score");
    expect(text).toContain("high risk");
    // It must reflect the scanner's counts, not invent findings.
    expect(text).toContain(`${report.summary.counts.high} high`);
  });

  it("does not leak secrets", () => {
    const text = explainReport(report);
    for (const secret of FIXTURE_SECRETS) {
      expect(text).not.toContain(secret);
    }
  });

  it("rejects unknown providers", () => {
    // @ts-expect-error deliberately passing an unsupported provider
    expect(() => explainReport(report, { provider: "openai" })).toThrow();
  });
});
