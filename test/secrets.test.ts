import { describe, it, expect } from "vitest";
import { isSecretKey, looksLikeSecretValue, redactValue } from "../src/core/secrets";

describe("isSecretKey", () => {
  it("matches common secret key names", () => {
    for (const k of ["ADMIN_TOKEN", "DB_PASSWORD", "API_KEY", "SMTP_PASS", "DATABASE_URL", "JWT_SECRET"]) {
      expect(isSecretKey(k)).toBe(true);
    }
  });

  it("does not match *_FILE keys (they point to a file, not a value)", () => {
    expect(isSecretKey("DB_PASSWORD_FILE")).toBe(false);
    expect(isSecretKey("PASSWORD_FILE")).toBe(false);
  });

  it("does not match unrelated keys", () => {
    for (const k of ["PUID", "TZ", "UPLOAD_LOCATION", "PORT"]) {
      expect(isSecretKey(k)).toBe(false);
    }
  });
});

describe("looksLikeSecretValue", () => {
  it("flags concrete literals, including weak placeholders", () => {
    expect(looksLikeSecretValue("supersecret")).toBe(true);
    expect(looksLikeSecretValue("changeme")).toBe(true);
  });

  it("ignores variable references, empties, and trivial values", () => {
    expect(looksLikeSecretValue("${DB_PASSWORD}")).toBe(false);
    expect(looksLikeSecretValue("$SECRET")).toBe(false);
    expect(looksLikeSecretValue("")).toBe(false);
    expect(looksLikeSecretValue("123")).toBe(false);
    expect(looksLikeSecretValue("true")).toBe(false);
  });
});

describe("redactValue", () => {
  it("never returns the original value", () => {
    const secret = "7x9KpQ2mZvL8nR4tW6yB1cJ3dF5gH0aS2eU4iO6pA8sD1fG3hJ5kL7mN9qR2tV4";
    const red = redactValue(secret);
    expect(red).not.toContain(secret);
    expect(red.length).toBeGreaterThan(0);
  });
});
