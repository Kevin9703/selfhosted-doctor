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

/** Case-insensitive: does the env KEY name look like it holds a secret? */
export function isSecretKey(key: string): boolean {
  const upper = key.toUpperCase();
  // A "_FILE" suffix points at a file path (e.g. DB_PASSWORD_FILE), not a value.
  if (upper.endsWith("_FILE")) {
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
  // Obvious non-secrets: pure booleans / yes-no / all-digit values.
  const lower = v.toLowerCase();
  if (lower === "true" || lower === "false" || lower === "yes" || lower === "no") {
    return false;
  }
  if (/^\d+$/.test(v)) {
    return false;
  }
  return true;
}

/** Redact a secret value for safe display. Must NEVER return the original value. */
export function redactValue(_value: string): string {
  return "***redacted***";
}
