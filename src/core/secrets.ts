/**
 * Secret detection and redaction helpers.
 *
 * These are deliberately conservative: rules use them to decide whether an env
 * KEY name or literal VALUE looks like a secret worth surfacing, and to redact
 * any value before it reaches a Finding. `redactValue` is a hard boundary — it
 * must never return any part of the original value.
 */

export const SECRET_KEY_KEYWORDS: string[] = [
  "PASSWORD",
  "PASS",
  "PASSWD",
  "TOKEN",
  "SECRET",
  "API_KEY",
  "APIKEY",
  "PRIVATE_KEY",
  "SMTP_PASS",
  "DATABASE_URL",
  "ACCESS_KEY",
  "CREDENTIAL",
  "AUTH",
];

/**
 * Suffixes that describe *configuration about* auth/tokens rather than the
 * secret value itself, e.g. AUTH_TYPE="public", TOKEN_METHOD="jwt",
 * SSO_PROVIDERS="google". Excluding these avoids flagging config enums as
 * secrets (a real credential is never named `*_TYPE`).
 */
const NON_SECRET_KEY_SUFFIXES: string[] = [
  "_FILE", // points at a file path (e.g. DB_PASSWORD_FILE), not a value
  "_TYPE",
  "_METHOD",
  "_MODE",
  "_ENABLED",
  "_DISABLED",
  "_PROVIDER",
  "_PROVIDERS",
  "_ALGORITHM",
  "_STRATEGY",
];

/** Case-insensitive: does the env KEY name look like it holds a secret? */
export function isSecretKey(key: string): boolean {
  const upper = key.toUpperCase();
  if (NON_SECRET_KEY_SUFFIXES.some((suffix) => upper.endsWith(suffix))) {
    return false;
  }
  return SECRET_KEY_KEYWORDS.some((keyword) => upper.includes(keyword));
}

/** Does a literal VALUE look like a real plaintext secret worth flagging? */
export function looksLikeSecretValue(value: string): boolean {
  const v = value.trim();
  if (v === "") {
    return false;
  }
  // Variable reference, not a literal secret.
  if (v.startsWith("$") || v.includes("${")) {
    return false;
  }
  // Too short to be a meaningful secret ("true", "80", "1", ...).
  if (v.length < 4) {
    return false;
  }
  // Obvious non-secrets: config enums / booleans / all-digit values. A real
  // credential is never literally "public" or "default".
  const lower = v.toLowerCase();
  if (NON_SECRET_VALUES.has(lower)) {
    return false;
  }
  if (/^\d+$/.test(v)) {
    return false;
  }
  return true;
}

/** Literal values that are config enums, never real secrets. */
const NON_SECRET_VALUES: Set<string> = new Set([
  "true",
  "false",
  "yes",
  "no",
  "on",
  "off",
  "none",
  "null",
  "nil",
  "undefined",
  "public",
  "private",
  "internal",
  "external",
  "local",
  "default",
  "auto",
  "enabled",
  "disabled",
  "development",
  "production",
  "staging",
]);

/** Redact a secret value for safe display. Must NEVER return the original value. */
export function redactValue(_value: string): string {
  return "***redacted***";
}
