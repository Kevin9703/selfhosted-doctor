/**
 * Exposure verdict: turn a deterministic scan Report into a single "can I open
 * this to the internet?" decision.
 *
 * This is a LAYER on top of the existing scanner/rules — it invents nothing. It
 * reads the findings the rules already produced (and the exposure map they drive)
 * and buckets them into the handful of things that actually decide whether a
 * self-hoster should expose a stack:
 *
 *   - blockers            → genuinely dangerous, don't expose until fixed
 *   - access              → public surface that must sit behind auth/Access/VPN
 *   - changeBeforePublic  → internal default secrets: fine on a private network,
 *                           must be changed before the host is on the internet
 *   - hygiene             → healthchecks, pinning, etc. — collapsed to a count
 *
 * Only ACTIVE findings (default + selected profiles) drive the verdict, exactly
 * like the existing score. Conditional (profile-gated) findings are surfaced as
 * a short "N more if you enable optional profiles" note, never mixed in.
 *
 * The exposure top-line is derived purely from ports published to 0.0.0.0 in the
 * compose file — no network probing. `EntryPoint` is deliberately a clean seam so
 * a future "is it actually reachable?" probe can annotate it.
 */
import type { Classification, ExposureEntry, Finding, Report } from "./model";
import { SERVICE_CATALOG } from "./services";
import { effectivePort } from "./rules/util";

export type Verdict = "dont-expose" | "behind-access" | "check-manually" | "looks-ok";

/** One thing the user must act on before (or instead of) exposing. */
export interface ExposeItem {
  /** Which section it belongs to. */
  kind: "blocker" | "access" | "change-before-public";
  ruleId: string;
  service?: string;
  /** Short, human headline. */
  headline: string;
  /** One-line "why it matters", when useful. */
  why?: string;
  /** Copy-pasteable fix, when a concrete one exists. */
  fix?: string;
  /** Multiple fixes, when several blockers on one service were grouped. */
  fixes?: string[];
  /** Suggested action phrased as a "→ do this" step (for access items). */
  action?: string;
}

/** A service reachable from the internet via published ports. */
export interface EntryPoint {
  service: string;
  /** Resolved host ports, e.g. ["80", "443"]. */
  ports: string[];
  /** Published ports whose `${VAR}` value could not be resolved to a number. */
  variablePorts?: string[];
  /**
   * Reserved seam for a future real-reachability probe. Static analysis can only
   * say a port is *published* to 0.0.0.0; it can't know if the host has a public
   * IP or a forwarded port. Left undefined by the static scanner.
   */
  reachable?: boolean;
}

export interface ExposeAssessment {
  /** Best-effort human name for the stack, e.g. "Dify" / "Vaultwarden". */
  stackLabel: string;
  verdict: Verdict;
  /** Public entry points derived from ports published to 0.0.0.0. */
  entryPoints: EntryPoint[];
  /** A Cloudflare Tunnel is present (another public path, not a published port). */
  hasTunnel: boolean;
  /** Top blockers (grouped per service, capped). See `blockerOverflow`. */
  blockers: ExposeItem[];
  /** Blockers hidden by the cap; total blockers = blockers.length + this. */
  blockerOverflow: number;
  access: ExposeItem[];
  changeBeforePublic: ExposeItem[];
  /** Count of active hygiene/reliability findings, collapsed (not enumerated). */
  hygieneCount: number;
  /** Active published ports we could not resolve to a number (dynamic config). */
  unresolvedPorts: { service: string; raw: string }[];
  /** Meaningful (high/medium) findings gated behind un-selected profiles. */
  conditionalHigh: number;
  conditionalMedium: number;
  /** Profiles that, if enabled, would add findings. */
  conditionalProfiles: string[];
  /** Extra caveats worth surfacing (e.g. a rule failed to run). */
  notes: string[];
}

/** Rules that are hard blockers on their own when active. */
const BLOCKER_RULES = new Set([
  "database-port-exposed",
  "docker-socket",
  "privileged",
  "host-network",
  "plaintext-secret",
]);

/** Rules that mean "public, but safe behind access control". */
const ACCESS_RULES = new Set(["cloudflared-no-access", "cloudflared-tunnel-to-risky"]);

/**
 * Findings that are security hygiene and get collapsed to a single count in
 * `expose`. Deliberately excludes `missing-labels` / `missing-resource-limits`
 * (pure ops/tidiness noise that will never get you hacked) — those are dropped
 * from the count entirely, see IGNORED_RULES.
 */
const HYGIENE_RULES = new Set([
  "missing-healthcheck",
  "missing-restart",
  "runs-as-root",
  "no-user",
  "latest-tag",
  "unpinned-image",
]);

/**
 * Rules that are neither a decision nor even hygiene-security: editorial context
 * (service-notes) and non-security ops noise (labels, resource limits). Dropped
 * from `expose` entirely — they belong in `scan`, not an exposure verdict.
 */
const IGNORED_RULES = new Set(["service-notes", "missing-labels", "missing-resource-limits"]);

/** Priority rank for ordering blockers: lower = shown first. */
const BLOCKER_RANK: Record<string, number> = {
  "database-port-exposed": 0,
  "plaintext-secret": 1,
  "exposed-port": 2,
  "docker-socket": 3,
  privileged: 3,
  "host-network": 3,
};

/** Max blockers shown before the rest are summarized as "+N more". */
const MAX_BLOCKERS_SHOWN = 4;
/** Max secret keys / ports named inside one clause before "+N more". */
const MAX_KEYS_SHOWN = 3;
const MAX_PORTS_SHOWN = 4;

type BlockerCategory = "db-port" | "app-port" | "secret" | "host";

/**
 * A single dangerous fact about one service, before per-service grouping and
 * per-category summarization. Structured (not pre-rendered) so many secrets or
 * ports on one service collapse to "N secrets (…, +M more)" instead of a run-on.
 */
interface RawBlocker {
  /** Owning service, or "" for file-level (e.g. .env) secrets. */
  service: string;
  ruleId: string;
  rank: number;
  category: BlockerCategory;
  /** secret: the env key. */
  key?: string;
  /** port: the resolved host port (numeric) when we could resolve it. */
  port?: string;
  /** port: the original expression when it could NOT be resolved (`${VAR}`). */
  portRaw?: string;
  /** host: the short "mounts the Docker socket" style fragment. */
  hostFragment?: string;
  why?: string;
  fix?: string;
}

function classificationOf(f: Finding): Classification {
  return f.classification ?? "active";
}

function isActive(f: Finding): boolean {
  return classificationOf(f) === "active";
}

/** A published port on a public host interface (0.0.0.0 / ::), matching isPublicPort. */
function isPublicExposure(e: ExposureEntry): boolean {
  const ip = e.hostIp && e.hostIp.length > 0 ? e.hostIp : "0.0.0.0";
  return ip === "0.0.0.0" || ip === "::";
}

function isResolved(port: string): boolean {
  return !port.includes("$");
}

/** The container port a port-finding refers to, read from its redacted evidence. */
function findingContainerPort(f: Finding): string | undefined {
  if (!f.evidence) return undefined;
  const arrow = f.evidence.indexOf("->");
  if (arrow < 0) return undefined;
  let rest = f.evidence.slice(arrow + 2);
  const slash = rest.lastIndexOf("/");
  if (slash >= 0) rest = rest.slice(0, slash);
  return effectivePort(rest.trim());
}

/** Find the exposure entry a port-finding maps to (by service + container port). */
function matchExposure(report: Report, f: Finding): ExposureEntry | undefined {
  const cp = findingContainerPort(f);
  const candidates = report.exposure.filter(
    (e) => (e.classification ?? "active") === "active" && isPublicExposure(e) && e.service === f.service,
  );
  if (candidates.length === 0) return undefined;
  if (cp !== undefined) {
    const exact = candidates.find((e) => effectivePort(e.containerPort) === cp);
    if (exact) return exact;
  }
  return candidates[0];
}

/** Extract the first `"quoted"` token from a title, e.g. the env key. */
function quoted(title: string): string | undefined {
  const m = title.match(/"([^"]+)"/);
  return m?.[1];
}

/** Build the copy-pasteable loopback-bind fix for a published port. */
function bindFix(e: ExposureEntry): { fix: string; reachablePort: string } {
  const host = effectivePort(e.hostPort);
  const cont = effectivePort(e.containerPort);
  return {
    fix: `"${host}:${cont}"  →  "127.0.0.1:${host}:${cont}"`,
    reachablePort: host,
  };
}

/** Join fragments naturally: "a", "a and b", "a, b and c". */
function joinAnd(parts: string[]): string {
  if (parts.length <= 1) return parts[0] ?? "";
  if (parts.length === 2) return `${parts[0]} and ${parts[1]}`;
  return `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}

/** Sort numeric ports ascending, non-numeric last (stable-ish, alpha). */
function sortPorts(ports: string[]): string[] {
  return [...ports].sort((a, b) => {
    const na = Number(a);
    const nb = Number(b);
    if (Number.isFinite(na) && Number.isFinite(nb)) return na - nb;
    if (Number.isFinite(na)) return -1;
    if (Number.isFinite(nb)) return 1;
    return a < b ? -1 : a > b ? 1 : 0;
  });
}

/** "A, B, C, +N more" from a de-duplicated list, naming at most `cap`. */
function nameSome(items: string[], cap: number): string {
  const shown = items.slice(0, cap);
  const more = items.length - shown.length;
  return more > 0 ? `${shown.join(", ")}, +${more} more` : shown.join(", ");
}

/** One clause summarizing however many secret keys, e.g. "hardcodes 4 real secrets (…)". */
function secretClause(keys: string[]): string {
  if (keys.length === 1) return `hardcodes a real secret (${keys[0]})`;
  return `hardcodes ${keys.length} real secrets (${nameSome(keys, MAX_KEYS_SHOWN)})`;
}

/** One clause summarizing published ports (resolved + unresolved `${VAR}`). */
function portClause(resolved: string[], unresolved: string[], isDb: boolean): string {
  const noun = isDb ? "database port" : "port";
  // Only variable ports — don't assert an unknown as a confident reachable port.
  if (resolved.length === 0) {
    return unresolved.length === 1
      ? `publishes a variable ${noun} (${unresolved[0]}, unresolved) to 0.0.0.0`
      : `publishes ${unresolved.length} variable ${noun}s (${nameSome(unresolved, MAX_PORTS_SHOWN)}, unresolved) to 0.0.0.0`;
  }
  const base =
    resolved.length === 1
      ? `publishes ${noun} ${resolved[0]} to 0.0.0.0`
      : `publishes ${resolved.length} ${noun}s (${nameSome(resolved, MAX_PORTS_SHOWN)}) to 0.0.0.0`;
  if (unresolved.length === 0) return base;
  const extra =
    unresolved.length === 1
      ? `plus a variable ${noun} (${unresolved[0]}, unresolved)`
      : `plus ${unresolved.length} variable ${noun}s (${nameSome(unresolved, MAX_PORTS_SHOWN)}, unresolved)`;
  return `${base}, ${extra}`;
}

/** Collect resolved + unresolved ports for a category from a fact list. */
function collectPorts(facts: RawBlocker[], category: BlockerCategory): { resolved: string[]; unresolved: string[] } {
  const resolved: string[] = [];
  const unresolved: string[] = [];
  for (const f of facts) {
    if (f.category !== category) continue;
    if (f.port !== undefined && !resolved.includes(f.port)) resolved.push(f.port);
    if (f.portRaw !== undefined && !unresolved.includes(f.portRaw)) unresolved.push(f.portRaw);
  }
  return { resolved: sortPorts(resolved), unresolved: sortPorts(unresolved) };
}

/**
 * One fix line for a port category. For a single port it's the exact per-port
 * bind fix (keeps host:container mappings like 8080:80 accurate); for several
 * it's "bind each …" with a concrete resolved example.
 */
function portCategoryFix(facts: RawBlocker[], category: BlockerCategory): string | undefined {
  const portFacts = facts.filter((f) => f.category === category);
  if (portFacts.length === 0) return undefined;
  // Prefer a resolved port as the worked example, not a `${VAR}` one.
  const example = portFacts.find((f) => f.port !== undefined) ?? portFacts[0]!;
  if (portFacts.length === 1) return example.fix;
  return example.fix ? `bind each published port to 127.0.0.1 (e.g. ${example.fix})` : undefined;
}

/**
 * Build one blocker ITEM for a service (or the file-level env-secrets group),
 * summarizing per category so many secrets/ports collapse to one clause each
 * rather than a run-on line.
 */
function buildGroupedItem(groupKey: string, facts: RawBlocker[]): ExposeItem & { rank: number } {
  facts.sort((a, b) => a.rank - b.rank);
  const rank = facts[0]?.rank ?? 99;
  const isEnvGroup = groupKey === ENV_SECRET_GROUP;
  const service = isEnvGroup ? "" : groupKey;

  const secretKeys: string[] = [];
  for (const f of facts) {
    if (f.category === "secret" && f.key && !secretKeys.includes(f.key)) secretKeys.push(f.key);
  }
  const hasUnkeyedSecret = facts.some((f) => f.category === "secret" && !f.key);
  const dbPorts = collectPorts(facts, "db-port");
  const appPorts = collectPorts(facts, "app-port");
  const hostFragments: string[] = [];
  for (const f of facts) {
    if (f.category === "host" && f.hostFragment && !hostFragments.includes(f.hostFragment)) {
      hostFragments.push(f.hostFragment);
    }
  }

  // File-level secrets (no owning service): name the files, never an empty label.
  if (isEnvGroup) {
    const item: ExposeItem & { rank: number } = {
      kind: "blocker",
      ruleId: "plaintext-secret",
      service: "",
      headline:
        secretKeys.length === 1
          ? `A real secret (${secretKeys[0]}) is hardcoded in a committed env file`
          : `${secretKeys.length} real secrets are hardcoded in committed env files (${nameSome(secretKeys, MAX_KEYS_SHOWN)})`,
      why: `These ship in files you would deploy — rotate them and keep real secrets out of version control.`,
      rank,
    };
    return item;
  }

  // Ordered clauses: db port → secret → app port → host control.
  const clauses: string[] = [];
  if (dbPorts.resolved.length + dbPorts.unresolved.length > 0) {
    clauses.push(portClause(dbPorts.resolved, dbPorts.unresolved, true));
  }
  if (secretKeys.length > 0) clauses.push(secretClause(secretKeys));
  else if (hasUnkeyedSecret) clauses.push("hardcodes a real secret");
  if (appPorts.resolved.length + appPorts.unresolved.length > 0) {
    clauses.push(portClause(appPorts.resolved, appPorts.unresolved, false));
  }
  const allHostControl = facts.every((f) => f.category === "host");
  if (hostFragments.length > 0 && !allHostControl) clauses.push(joinAnd(hostFragments));

  const headline =
    allHostControl && hostFragments.length > 0
      ? `${service} effectively has root on the host — it ${joinAnd(hostFragments)}`
      : `${service} ${joinAnd(clauses)}`;

  // Build a compact, de-duplicated fix list (one per category, not per port).
  const fixes: string[] = [];
  const dbFix = portCategoryFix(facts, "db-port");
  if (dbFix) fixes.push(dbFix);
  const appFix = portCategoryFix(facts, "app-port");
  if (appFix) fixes.push(appFix);
  const secretFix = facts.find((f) => f.category === "secret")?.fix;
  if ((secretKeys.length > 0 || hasUnkeyedSecret) && secretFix) fixes.push(secretFix);
  for (const f of facts) {
    if (f.category === "host" && f.fix && !fixes.includes(f.fix)) fixes.push(f.fix);
  }

  const item: ExposeItem & { rank: number } = {
    kind: "blocker",
    ruleId: [...new Set(facts.map((f) => f.ruleId))].join("+"),
    service,
    headline,
    rank,
  };
  if (fixes.length === 1) item.fix = fixes[0];
  else if (fixes.length > 1) item.fixes = fixes;
  // Keep a short "why" only when the top fact adds signal and the headline
  // doesn't already say it (host-control headline is self-explanatory).
  const topWhy = facts[0]?.why;
  if (!allHostControl && topWhy && topWhy.length < 90) item.why = topWhy;
  return item;
}

/** Synthetic group key for file-level (env) secrets with no owning service. */
const ENV_SECRET_GROUP = " env-secrets";

/**
 * Collapse the raw dangerous facts into one blocker ITEM per service (so many
 * secrets or ports on one service read as one decision), then rank and cap.
 * File-level env secrets are grouped together under one file-oriented item.
 */
function groupBlockers(raw: RawBlocker[]): { blockers: ExposeItem[]; overflow: number } {
  const byGroup = new Map<string, RawBlocker[]>();
  for (const b of raw) {
    const key = b.service !== "" ? b.service : ENV_SECRET_GROUP;
    const list = byGroup.get(key) ?? [];
    list.push(b);
    byGroup.set(key, list);
  }

  const grouped: (ExposeItem & { rank: number })[] = [];
  for (const [key, facts] of byGroup) grouped.push(buildGroupedItem(key, facts));

  grouped.sort((a, b) => (a.rank !== b.rank ? a.rank - b.rank : (a.service ?? "") < (b.service ?? "") ? -1 : 1));

  const shown = grouped.slice(0, MAX_BLOCKERS_SHOWN).map(({ rank: _rank, ...item }) => item);
  const overflow = Math.max(0, grouped.length - MAX_BLOCKERS_SHOWN);
  return { blockers: shown, overflow };
}

/**
 * Group active, public exposure into per-service entry points, separating ports
 * we could resolve to a number from unresolved `${VAR}` ports — we don't present
 * an unknown as a confident reachable port.
 */
function buildEntryPoints(report: Report): EntryPoint[] {
  const resolvedByService = new Map<string, string[]>();
  const variableByService = new Map<string, string[]>();
  const order: string[] = [];
  for (const e of report.exposure) {
    if ((e.classification ?? "active") !== "active") continue;
    if (!isPublicExposure(e)) continue;
    if (!resolvedByService.has(e.service)) {
      resolvedByService.set(e.service, []);
      variableByService.set(e.service, []);
      order.push(e.service);
    }
    const port = effectivePort(e.hostPort);
    const bucket = isResolved(port) ? resolvedByService.get(e.service)! : variableByService.get(e.service)!;
    if (!bucket.includes(port)) bucket.push(port);
  }
  const points: EntryPoint[] = [];
  for (const service of order) {
    const ports = sortPorts(resolvedByService.get(service) ?? []);
    const variablePorts = sortPorts(variableByService.get(service) ?? []);
    const point: EntryPoint = { service, ports };
    if (variablePorts.length > 0) point.variablePorts = variablePorts;
    points.push(point);
  }
  points.sort((a, b) => (a.service < b.service ? -1 : a.service > b.service ? 1 : 0));
  return points;
}

/** Derive a friendly stack name: a detected app first, else the path. */
function deriveStackLabel(report: Report): string {
  // Prefer a detected non-infra app (sensitive apps win), e.g. Vaultwarden.
  const infra = new Set(["database", "cache", "proxy", "tunnel", "other"]);
  const appIds: string[] = [];
  for (const s of report.services) {
    if (s.detectedType) appIds.push(s.detectedType);
  }
  const defsById = new Map(SERVICE_CATALOG.map((d) => [d.id, d] as const));
  const sensitive = appIds.map((id) => defsById.get(id)).find((d) => d?.sensitive);
  if (sensitive) return sensitive.label;
  const app = appIds.map((id) => defsById.get(id)).find((d) => d && !infra.has(d.category));
  if (app) return app.label;
  return labelFromPath(report.target);
}

const GENERIC_DIR_SEGMENTS = new Set([
  "docker",
  "compose",
  "docker-compose",
  "deploy",
  "deployment",
  "deployments",
  "stack",
  "stacks",
  "config",
  "configs",
  "conf",
  "src",
  "app",
  "apps",
  ".",
  "..",
]);

function capitalize(s: string): string {
  if (s.length === 0) return s;
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Best-effort stack name from a target path, skipping generic dir/file names. */
export function labelFromPath(target: string): string {
  const segments = target.split(/[\\/]/).filter((s) => s.length > 0);
  for (let i = segments.length - 1; i >= 0; i--) {
    const seg = segments[i];
    if (seg === undefined) continue;
    if (/\.(ya?ml|env)$/i.test(seg)) continue; // skip the compose/env filename
    if (GENERIC_DIR_SEGMENTS.has(seg.toLowerCase())) continue;
    return capitalize(seg);
  }
  return "This stack";
}

/**
 * Assess whether a scanned stack is safe to expose to the internet.
 *
 * Pure function of the deterministic Report: same report in, same verdict out.
 */
export function assessExposure(report: Report): ExposeAssessment {
  const rawBlockers: RawBlocker[] = [];
  const access: ExposeItem[] = [];
  let hygieneCount = 0;
  const notes: string[] = [];

  // Group front-door (reverse proxy) exposures per service so nginx 80+443 read
  // as one "front door" item, not two.
  const frontDoorPorts = new Map<string, string[]>();
  const defaultSecrets: { service?: string; key: string }[] = [];

  for (const f of report.findings) {
    if (!isActive(f)) continue;
    if (f.ruleId === "rule-error") {
      notes.push(`A rule (${f.title}) failed to run, so this assessment may be incomplete.`);
      continue;
    }
    if (IGNORED_RULES.has(f.ruleId)) continue;

    const service = f.service ?? "";

    // Port blockers: a raw app/debug/admin port (exposed-port high) or a database
    // port published to the public. Reverse-proxy front doors are exposed-port
    // MEDIUM (the rule already made that call) → access, not blocker.
    if (f.ruleId === "database-port-exposed" || (f.ruleId === "exposed-port" && f.severity === "high")) {
      const e = matchExposure(report, f);
      const isDb = f.ruleId === "database-port-exposed";
      const port = e ? bindFix(e).reachablePort : (findingContainerPort(f) ?? "?");
      const resolved = isResolved(port);
      const fix = e ? bindFix(e).fix : f.recommendation;
      rawBlockers.push({
        service,
        ruleId: f.ruleId,
        rank: BLOCKER_RANK[f.ruleId] ?? 2,
        category: isDb ? "db-port" : "app-port",
        ...(resolved ? { port } : { portRaw: port }),
        why: isDb
          ? `An exposed database is a direct path to all of its data.`
          : `Anyone on the internet could reach ${service} directly.`,
        ...(fix ? { fix } : {}),
      });
      continue;
    }

    if (f.ruleId === "exposed-port" && f.severity === "medium") {
      const e = matchExposure(report, f);
      const port = e ? effectivePort(e.hostPort) : undefined;
      const list = f.service ? frontDoorPorts.get(f.service) ?? [] : [];
      if (port && !list.includes(port)) list.push(port);
      if (f.service) frontDoorPorts.set(f.service, list);
      continue;
    }

    if (f.ruleId === "plaintext-secret") {
      const key = quoted(f.title);
      rawBlockers.push({
        service,
        ruleId: f.ruleId,
        rank: BLOCKER_RANK[f.ruleId] ?? 1,
        category: "secret",
        ...(key ? { key } : {}),
        why: `It ships in the exact file you would deploy — not a template.`,
        ...(f.recommendation ? { fix: f.recommendation } : {}),
      });
      continue;
    }

    if (BLOCKER_RULES.has(f.ruleId)) {
      const hostFragment =
        f.ruleId === "docker-socket"
          ? "mounts the Docker socket"
          : f.ruleId === "privileged"
            ? "runs in privileged mode"
            : f.ruleId === "host-network"
              ? "uses the host network"
              : f.title;
      rawBlockers.push({
        service,
        ruleId: f.ruleId,
        rank: BLOCKER_RANK[f.ruleId] ?? 3,
        category: "host",
        hostFragment,
        why: f.detail,
        ...(f.recommendation ? { fix: f.recommendation } : {}),
      });
      continue;
    }

    if (ACCESS_RULES.has(f.ruleId)) {
      const risky = f.ruleId === "cloudflared-tunnel-to-risky";
      access.push({
        kind: "access",
        ruleId: f.ruleId,
        service: f.service,
        // "detected" wording: we can't see an Access policy or auth proxy that
        // lives outside the compose file, so we don't assert one is missing.
        headline: risky
          ? `A Cloudflare Tunnel routes to a sensitive service — no Access policy detected`
          : `Cloudflare Tunnel — no Access policy detected in front of it`,
        action: risky
          ? `require Cloudflare Access + MFA before this goes public`
          : `add a Cloudflare Access policy (email / IdP / MFA)`,
      });
      continue;
    }

    if (f.ruleId === "default-secret-fallback") {
      const key = quoted(f.title);
      if (key) defaultSecrets.push({ service: f.service, key });
      continue;
    }

    if (HYGIENE_RULES.has(f.ruleId)) {
      hygieneCount += 1;
      continue;
    }

    // Anything else active and non-info-critical is treated as hygiene noise.
    if (f.severity === "info") {
      hygieneCount += 1;
    }
  }

  // A tunnel routing to a sensitive service is the specific case of "tunnel has
  // no Access" — don't show both. Drop the generic line when the specific one is
  // present so Vaultwarden shows one tunnel item, not two.
  if (access.some((i) => i.ruleId === "cloudflared-tunnel-to-risky")) {
    for (let i = access.length - 1; i >= 0; i--) {
      if (access[i]?.ruleId === "cloudflared-no-access") access.splice(i, 1);
    }
  }

  // Fold grouped front-door exposures into single access items.
  for (const [service, ports] of frontDoorPorts) {
    const portList = ports.length > 0 ? ports.join("/") : "";
    access.push({
      kind: "access",
      ruleId: "exposed-port",
      service,
      // "detected" wording: an auth proxy / Cloudflare Access policy may sit in
      // front of this outside the compose file — we can't see it, so we don't
      // claim it's absent.
      headline: portList
        ? `${service} is your front door (publishes ${portList}) — no access control detected in front of it`
        : `${service} is your front door — no access control detected in front of it`,
      action: `put it behind Cloudflare Access, a VPN, or an auth proxy`,
    });
  }

  // Aggregate internal default secrets into one "change before public" item.
  const changeBeforePublic: ExposeItem[] = [];
  if (defaultSecrets.length > 0) {
    const serviceCount = new Set(defaultSecrets.map((d) => d.service ?? "")).size;
    const distinctKeys: string[] = [];
    for (const d of defaultSecrets) {
      if (!distinctKeys.includes(d.key)) distinctKeys.push(d.key);
    }
    // Make the service count and the key count consistent so N services / M keys
    // never reads like an off-by-one.
    const keyNote =
      distinctKeys.length !== serviceCount
        ? ` (${distinctKeys.length} shared key${distinctKeys.length === 1 ? "" : "s"})`
        : "";
    changeBeforePublic.push({
      kind: "change-before-public",
      ruleId: "default-secret-fallback",
      headline: `${serviceCount} internal service${serviceCount === 1 ? "" : "s"} fall back to built-in default secrets${keyNote}`,
      why: `Fine on a private network; MUST be changed if this host is on the internet.`,
      action: `set real values for ${distinctKeys.join(", ")}`,
    });
  }

  // Group raw blockers per service, rank, and cap.
  const { blockers, overflow: blockerOverflow } = groupBlockers(rawBlockers);

  // Entry points + unresolved (dynamic) ports we couldn't pin down.
  const entryPoints = buildEntryPoints(report);
  const unresolvedPorts: { service: string; raw: string }[] = [];
  for (const e of report.exposure) {
    if ((e.classification ?? "active") !== "active") continue;
    if (!isPublicExposure(e)) continue;
    const host = effectivePort(e.hostPort);
    const cont = effectivePort(e.containerPort);
    if (!isResolved(host) || !isResolved(cont)) {
      unresolvedPorts.push({ service: e.service, raw: `${e.hostPort}->${e.containerPort}` });
    }
  }

  const hasTunnel =
    report.services.some((s) => s.detectedType === "cloudflared") ||
    report.findings.some((f) => f.ruleId.startsWith("cloudflared"));

  // Conditional (profile-gated) summary.
  let conditionalHigh = 0;
  let conditionalMedium = 0;
  const conditionalProfiles = new Set<string>();
  for (const f of report.findings) {
    if (classificationOf(f) !== "conditional") continue;
    if (f.severity === "high") conditionalHigh += 1;
    else if (f.severity === "medium") conditionalMedium += 1;
    for (const p of f.profiles ?? []) conditionalProfiles.add(p);
  }
  for (const e of report.exposure) {
    if (e.classification !== "conditional") continue;
    for (const p of e.profiles ?? []) conditionalProfiles.add(p);
  }

  const verdict = decideVerdict({ blockers, access, unresolvedPorts, entryPoints });

  return {
    stackLabel: deriveStackLabel(report),
    verdict,
    entryPoints,
    hasTunnel,
    blockers,
    blockerOverflow,
    access,
    changeBeforePublic,
    hygieneCount,
    unresolvedPorts,
    conditionalHigh,
    conditionalMedium,
    conditionalProfiles: [...conditionalProfiles].sort(),
    notes,
  };
}

/**
 * Choose one of the four verdicts. Precedence, most severe first:
 *   1. any active blocker            → don't expose
 *   2. an unresolved dynamic port    → can't decide, check manually
 *   3. public surface needs access   → behind access
 *   4. otherwise                     → looks ok (only hygiene / internal defaults)
 */
export function decideVerdict(input: {
  blockers: ExposeItem[];
  access: ExposeItem[];
  unresolvedPorts: { service: string; raw: string }[];
  entryPoints: EntryPoint[];
}): Verdict {
  if (input.blockers.length > 0) return "dont-expose";
  if (input.unresolvedPorts.length > 0) return "check-manually";
  if (input.access.length > 0) return "behind-access";
  return "looks-ok";
}
