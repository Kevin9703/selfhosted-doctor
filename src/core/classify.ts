/**
 * Finding classification: decide whether each finding is active, conditional
 * (gated behind an un-selected Compose profile), or template (from an
 * example/placeholder env file).
 *
 * This is the trust layer that keeps a big upstream Compose file from reading as
 * pure fear: rules find issues, this decides how much they should count.
 */
import path from "node:path";
import type { ComposeService, Finding, ScanContext } from "./model";

/**
 * True when the path names a template/example env file, whose secret-looking
 * values are expected placeholders rather than real committed secrets:
 *  - a basename ending in `.example`, `.sample`, or `.template`
 *  - an env file (`.env`, `.env.*`, `*.env`) located under an `examples/` dir
 */
export function isEnvTemplateFile(filePath: string): boolean {
  const base = path.basename(filePath).toLowerCase();
  if (base.endsWith(".example") || base.endsWith(".sample") || base.endsWith(".template")) {
    return true;
  }
  const isEnvName = base === ".env" || base.startsWith(".env.") || base.endsWith(".env");
  if (isEnvName && /(^|[\\/])examples?([\\/])/i.test(filePath)) {
    return true;
  }
  return false;
}

export interface ClassifyOptions {
  /** Profiles selected via `--profile` (scored as if active). */
  profiles?: string[];
  /** `--all-profiles`: treat every profile as active. */
  allProfiles?: boolean;
}

/** Whether a service runs given the selected profiles. */
export function isServiceActive(service: ComposeService, opts: ClassifyOptions = {}): boolean {
  if (opts.allProfiles === true) return true;
  if (service.profiles.length === 0) return true;
  const selected = new Set(opts.profiles ?? []);
  return service.profiles.some((p) => selected.has(p));
}

/**
 * Assign `classification` (and gating `profiles`) to every finding based on the
 * service it belongs to and the selected Compose profiles. Findings a rule has
 * already classified (e.g. template secrets) are left untouched.
 */
export function classifyFindings(
  findings: Finding[],
  ctx: ScanContext,
  opts: ClassifyOptions = {},
): Finding[] {
  const serviceByName = new Map<string, ComposeService>();
  for (const service of ctx.services) {
    if (!serviceByName.has(service.name)) serviceByName.set(service.name, service);
  }

  return findings.map((finding) => {
    // A rule already decided (template secrets set classification directly).
    if (finding.classification) return finding;

    if (finding.service) {
      const service = serviceByName.get(finding.service);
      if (service && !isServiceActive(service, opts)) {
        return { ...finding, classification: "conditional" as const, profiles: [...service.profiles] };
      }
    }
    return { ...finding, classification: "active" as const };
  });
}
