import { describe, it, expect } from "vitest";
import { ctxFromCompose } from "./helpers";
import { buildReport, scan } from "../src/core/scanner";
import { parseComposeServices } from "../src/core/compose";
import type { LoadedFile } from "../src/core/model";

const STAMP = { generatedAt: "2026-07-01T00:00:00.000Z" };

const composeWithProfile =
  `services:\n` +
  `  app:\n    image: app:1\n    ports: ["8080:80"]\n` +
  `  optional-db:\n    image: postgres:16\n    profiles: [heavy]\n    ports: ["5432:5432"]\n`;

const composeAppOnly = `services:\n  app:\n    image: app:1\n    ports: ["8080:80"]\n`;

describe("compose profiles", () => {
  it("parses profiles onto services (empty when absent)", () => {
    const svcs = parseComposeServices({
      path: "c.yml",
      kind: "compose",
      content: composeWithProfile,
    } as LoadedFile);
    expect(svcs.find((s) => s.name === "optional-db")!.profiles).toEqual(["heavy"]);
    expect(svcs.find((s) => s.name === "app")!.profiles).toEqual([]);
  });

  it("classifies profile-gated findings as conditional and excludes them from the default score", () => {
    const report = buildReport(ctxFromCompose(composeWithProfile), STAMP);
    const dbFinding = report.findings.find((f) => f.ruleId === "database-port-exposed");
    expect(dbFinding?.classification).toBe("conditional");
    expect(dbFinding?.profiles).toEqual(["heavy"]);

    // The conditional database must not change the default score: it matches the
    // score of the same stack with the optional service removed entirely.
    const appOnly = buildReport(ctxFromCompose(composeAppOnly), STAMP);
    expect(report.summary.riskScore).toBe(appOnly.summary.riskScore);
  });

  it("scores the profile-gated service once it is selected", () => {
    const base = buildReport(ctxFromCompose(composeWithProfile), STAMP);
    const scored = buildReport(ctxFromCompose(composeWithProfile), { ...STAMP, profiles: ["heavy"] });
    expect(scored.summary.riskScore).toBeLessThan(base.summary.riskScore);
    expect(scored.findings.find((f) => f.ruleId === "database-port-exposed")?.classification).toBe("active");
  });

  it("classifies exposure entries by selected profile", () => {
    const base = buildReport(ctxFromCompose(composeWithProfile), STAMP);
    const exposedDb = base.exposure.find((e) => e.service === "optional-db");
    expect(exposedDb).toMatchObject({ classification: "conditional", profiles: ["heavy"] });

    const selected = buildReport(ctxFromCompose(composeWithProfile), { ...STAMP, profiles: ["heavy"] });
    expect(selected.exposure.find((e) => e.service === "optional-db")?.classification).toBe("active");
  });

  it("acceptance: a profiles:[milvus] public port lowers the score only with --profile / --all-profiles", () => {
    const base = scan("test/fixtures/dify-like", STAMP).summary.riskScore;
    const withMilvus = scan("test/fixtures/dify-like", { ...STAMP, profiles: ["milvus"] }).summary.riskScore;
    const withAll = scan("test/fixtures/dify-like", { ...STAMP, allProfiles: true }).summary.riskScore;
    expect(withMilvus).toBeLessThan(base);
    expect(withAll).toBeLessThan(withMilvus);
  });
});
