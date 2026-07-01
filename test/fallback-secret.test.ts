import { describe, it, expect } from "vitest";
import { ctxFromCompose } from "./helpers";
import { rule as defaultSecretFallback } from "../src/core/rules/default-secret-fallback";
import { parseComposeServices } from "../src/core/compose";
import type { LoadedFile } from "../src/core/model";

const svc = (yaml: string) =>
  parseComposeServices({ path: "c.yml", kind: "compose", content: yaml } as LoadedFile);

describe("${VAR:-default} parsing", () => {
  it("captures the fallback default and marks it a reference", () => {
    const [s] = svc(`services:\n  a:\n    image: x\n    environment:\n      DB_PASSWORD: \${DB_PASSWORD:-difyai123456}\n`);
    const entry = s!.environment.find((e) => e.key === "DB_PASSWORD")!;
    expect(entry.isReference).toBe(true);
    expect(entry.fallbackDefault).toBe("difyai123456");
  });

  it("has no fallbackDefault for a plain reference", () => {
    const [s] = svc(`services:\n  a:\n    image: x\n    environment:\n      DB_PASSWORD: \${DB_PASSWORD}\n`);
    expect(s!.environment.find((e) => e.key === "DB_PASSWORD")!.fallbackDefault).toBeUndefined();
  });
});

describe("default-secret-fallback rule", () => {
  it("acceptance: ${VAR:-secret} is flagged high, ${VAR} is not", () => {
    const flagged = defaultSecretFallback.run(
      ctxFromCompose(`services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: \${DB_PASSWORD:-difyai123456}\n`),
    );
    expect(flagged).toHaveLength(1);
    expect(flagged[0]).toMatchObject({ severity: "high", service: "db" });

    const clean = defaultSecretFallback.run(
      ctxFromCompose(`services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: \${DB_PASSWORD}\n`),
    );
    expect(clean).toHaveLength(0);
  });

  it("redacts the fallback value in evidence", () => {
    const [f] = defaultSecretFallback.run(
      ctxFromCompose(`services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: \${DB_PASSWORD:-difyai123456}\n`),
    );
    expect(f!.evidence).toBeDefined();
    expect(f!.evidence).not.toContain("difyai123456");
  });
});
