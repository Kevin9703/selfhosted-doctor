import { describe, it, expect } from "vitest";
import { scan } from "../src/core/scanner";
import { renderReport } from "../src/report";
import { renderMarkdown } from "../src/report/markdown";
import { renderTerminal, scoreColor } from "../src/report/terminal";
import { renderJson } from "../src/report/json";
import { FIXTURE_SECRETS } from "./helpers";
import type { Report } from "../src/core/model";

const report = scan("examples/nextcloud-db", { generatedAt: "2026-07-01T00:00:00.000Z" });
const ESC = String.fromCharCode(27); // ANSI escape introducer

describe("markdown report", () => {
  const md = renderMarkdown(report);

  it("contains all required sections", () => {
    for (const heading of [
      "## Summary",
      "## High Risk",
      "## Medium Risk",
      "## Low Risk",
      "## Exposure Map",
      "## Service Notes",
      "## Suggested Fixes",
      "## Disclaimer",
    ]) {
      expect(md).toContain(heading);
    }
  });
});

describe("terminal report", () => {
  it("renders without ANSI codes when color is disabled", () => {
    const out = renderTerminal(report, { color: false });
    expect(out).toContain("selfhosted-doctor report");
    expect(out.includes(ESC)).toBe(false);
  });

  it("maps the risk score to the correct color band (higher = safer)", () => {
    expect(scoreColor(100)).toBe("green");
    expect(scoreColor(67)).toBe("green"); // boundary
    expect(scoreColor(66)).toBe("yellow");
    expect(scoreColor(34)).toBe("yellow"); // boundary
    expect(scoreColor(33)).toBe("red");
    expect(scoreColor(0)).toBe("red");
  });

  it("surfaces rule failures in a Diagnostics section", () => {
    const withError: Report = {
      ...report,
      findings: [
        {
          ruleId: "rule-error",
          severity: "info",
          title: 'Rule "exposed-port" failed and was skipped',
          detail: "The rule threw an error.",
        },
      ],
    };
    const out = renderTerminal(withError, { color: false });
    expect(out).toContain("Diagnostics");
    expect(out).toContain('Rule "exposed-port" failed and was skipped');
  });
});

describe("json report", () => {
  it("round-trips and is pretty by default", () => {
    const json = renderJson(report);
    expect(() => JSON.parse(json)).not.toThrow();
    expect(json).toContain("\n");
  });
});

describe("redaction across every format", () => {
  it("no format leaks a raw secret value", () => {
    for (const format of ["terminal", "json", "markdown"] as const) {
      const out = renderReport(report, format, { color: false });
      for (const secret of FIXTURE_SECRETS) {
        expect(out).not.toContain(secret);
      }
    }
  });
});
