/**
 * Static parsing of cloudflared tunnel configuration files.
 *
 * This never executes cloudflared or touches the network — it just reads the
 * YAML config and extracts ingress rules plus a coarse "does this mention
 * Access?" hint. It must never throw: unrecognizable input yields undefined.
 */

import { parse } from "yaml";
import type { LoadedFile, CloudflareTunnel, TunnelIngress } from "./model";

/** Statically parse a cloudflared config file. Returns undefined if the file is not a recognizable tunnel config. Never throws. */
export function parseCloudflaredConfig(file: LoadedFile): CloudflareTunnel | undefined {
  let doc: unknown;
  try {
    doc = parse(file.content);
  } catch {
    return undefined;
  }

  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    return undefined;
  }

  const record = doc as Record<string, unknown>;

  const rawIngress = record["ingress"];
  const hasIngress = Array.isArray(rawIngress);
  const hasTunnel = typeof record["tunnel"] === "string";
  const hasCredentials =
    typeof record["credentials-file"] === "string" ||
    typeof record["credentials_file"] === "string";

  if (!hasIngress && !hasTunnel && !hasCredentials) {
    return undefined;
  }

  const ingress: TunnelIngress[] = [];
  if (hasIngress) {
    for (const item of rawIngress as unknown[]) {
      if (item === null || typeof item !== "object" || Array.isArray(item)) {
        continue;
      }
      const entry = item as Record<string, unknown>;
      const rule: TunnelIngress = {};
      const hostname = entry["hostname"];
      const service = entry["service"];
      if (typeof hostname === "string") {
        rule.hostname = hostname;
      }
      if (typeof service === "string") {
        rule.service = service;
      }
      ingress.push(rule);
    }
  }

  const hasAccessHint = /access/i.test(file.content);

  return {
    file: file.path,
    ingress,
    hasAccessHint,
  };
}
