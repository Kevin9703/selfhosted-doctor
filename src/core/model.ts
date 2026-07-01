/**
 * Core data model for selfhosted-doctor.
 *
 * Everything downstream — rules, reporters, MCP, AI explain — operates on these
 * types. Findings are produced only by deterministic rules; secret values are
 * redacted before they ever reach a Finding, so no formatter can leak them.
 */

export type Severity = "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["high", "medium", "low", "info"];

/**
 * Where a finding applies, so reports can prioritize instead of treating every
 * finding as equally urgent:
 *  - "active": applies to the default/running stack (scored)
 *  - "conditional": only applies when an optional Compose profile is enabled
 *  - "template": found in a template/example env file (default placeholders)
 */
export type Classification = "active" | "conditional" | "template";

export const CLASSIFICATIONS: Classification[] = ["active", "conditional", "template"];

/** A normalized port mapping parsed from Compose short or long syntax. */
export interface PortMapping {
  /** Original value as written in the Compose file. */
  raw: string;
  /** Host interface the port binds to, e.g. "0.0.0.0" or "127.0.0.1". */
  hostIp?: string;
  /** Published host port (may be a range like "8000-8005"). */
  hostPort?: string;
  /** Container-side port. */
  containerPort: string;
  /** "tcp" (default) or "udp". */
  protocol: string;
  /** True when the port is published to the host (has a host binding). */
  published: boolean;
}

/** A normalized volume mount parsed from Compose short or long syntax. */
export interface VolumeMount {
  raw: string;
  source?: string;
  target?: string;
  readOnly: boolean;
}

/** A single environment entry, keeping track of where it came from. */
export interface EnvEntry {
  key: string;
  value: string;
  /** True when the value is a "${VAR}" reference rather than a literal. */
  isReference: boolean;
  /**
   * The default baked into a "${VAR:-default}" / "${VAR-default}" fallback, if
   * any. This is the value a self-hoster silently ships when they never set the
   * variable — a common source of default-credential risk.
   */
  fallbackDefault?: string;
}

/** A normalized Compose service. */
export interface ComposeService {
  /** Service key in the Compose file. */
  name: string;
  image?: string;
  containerName?: string;
  privileged: boolean;
  networkMode?: string;
  ports: PortMapping[];
  /** Internal-only ports declared via `expose`. */
  expose: string[];
  /**
   * Compose `profiles:` this service belongs to. Empty means the service is
   * always started (active). A non-empty list means the service only runs when
   * one of these profiles is enabled — its findings are conditional.
   */
  profiles: string[];
  volumes: VolumeMount[];
  environment: EnvEntry[];
  hasHealthcheck: boolean;
  healthcheckDisabled: boolean;
  restart?: string;
  user?: string;
  labels: Record<string, string>;
  hasResourceLimits: boolean;
  /** File this service was defined in. */
  file: string;
  /** Original raw node for rules that need to look deeper. */
  raw: Record<string, unknown>;
}

/** A file that was loaded and considered during a scan. */
export interface LoadedFile {
  path: string;
  kind: "compose" | "env" | "cloudflared";
  content: string;
}

/** A parsed .env-style file (KEY=value lines). */
export interface EnvFile {
  path: string;
  entries: EnvEntry[];
}

/** Cloudflare Tunnel ingress rule discovered by static scan. */
export interface TunnelIngress {
  hostname?: string;
  service?: string;
}

/** Result of statically scanning cloudflared config. */
export interface CloudflareTunnel {
  file: string;
  ingress: TunnelIngress[];
  hasAccessHint: boolean;
}

/** A single security finding produced by a rule. */
export interface Finding {
  ruleId: string;
  severity: Severity;
  title: string;
  /** Service the finding relates to, when applicable. */
  service?: string;
  /** File the finding relates to, when applicable. */
  file?: string;
  /** Human-readable description of the risk. */
  detail: string;
  /** Concrete, actionable recommendation. */
  recommendation?: string;
  /** Redacted evidence string. Never contains raw secret values. */
  evidence?: string;
  /**
   * Where this finding applies. Set by the classification pass; rules may leave
   * it undefined (treated as "active"). Reports and scoring key off this.
   */
  classification?: Classification;
  /**
   * When `classification` is "conditional", the Compose profile(s) that must be
   * enabled for the finding's service to run.
   */
  profiles?: string[];
}

/** One published-port entry for the exposure map. */
export interface ExposureEntry {
  service: string;
  hostIp: string;
  hostPort: string;
  containerPort: string;
  protocol: string;
  /** Whether this exposure applies to the active/default stack or a profile. */
  classification?: Classification;
  /** Required profiles when the exposure is conditional. */
  profiles?: string[];
}

/** Per-service summary shown in reports. */
export interface ServiceSummary {
  name: string;
  image?: string;
  /** Detected well-known service id, e.g. "vaultwarden". */
  detectedType?: string;
  publishedPorts: number;
  findingCounts: Record<Severity, number>;
}

/** Severity counts plus a total. */
export type SeverityCounts = Record<Severity, number> & { total: number };

/** One capped scoring bucket's contribution to the penalty. */
export interface ScoreBucket {
  bucket: string;
  penalty: number;
  cap: number;
}

export interface ReportSummary {
  /** 0–100, computed from ACTIVE findings only (higher is safer). */
  riskScore: number;
  /** Counts across ALL findings, regardless of classification. */
  counts: SeverityCounts;
  /** Counts of active findings (these drive the score). */
  active: SeverityCounts;
  /** Counts of conditional (profile-gated) findings. */
  conditional: SeverityCounts;
  /** Counts of template/example findings. */
  template: SeverityCounts;
  /** Per-bucket penalty breakdown behind the score (active findings only). */
  scoreBreakdown: ScoreBucket[];
}

/**
 * Everything a rule needs to evaluate a scan. Lives here (not in scanner.ts) so
 * that rules and the scanner can both import it without a circular dependency.
 */
export interface ScanContext {
  target: string;
  files: string[];
  services: ComposeService[];
  envFiles: EnvFile[];
  tunnels: CloudflareTunnel[];
}

/** A deterministic security rule. Rules are the ONLY producers of findings. */
export interface Rule {
  id: string;
  /** Short description of what the rule checks. */
  description: string;
  run(ctx: ScanContext): Finding[];
}

/** The full deterministic scan result. This is the AI-ready shape. */
export interface Report {
  tool: string;
  version: string;
  generatedAt: string;
  target: string;
  files: string[];
  summary: ReportSummary;
  findings: Finding[];
  exposure: ExposureEntry[];
  services: ServiceSummary[];
}
