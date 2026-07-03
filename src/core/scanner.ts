/**
 * Scan orchestrator: load → parse → run rules → assemble the Report.
 *
 * This is the single entry point the CLI, MCP server, and tests use. It is
 * deterministic: given the same files it always produces the same Report.
 */
import { loadInputs } from "./loader";
import { parseComposeServices, parseEnvFile } from "./compose";
import {
  maybeLoadDockerInspectFile,
  containersToServices,
  type DockerInspectContainer,
} from "./docker-inspect";
import { parseCloudflaredConfig } from "./cloudflare";
import { detectServiceType } from "./services";
import { runRules } from "./rules";
import { isPublicPort } from "./rules/util";
import { classifyFindings, isServiceActive } from "./classify";
import { scoreActiveFindings } from "./score";
import {
  type Classification,
  type CloudflareTunnel,
  type ComposeService,
  type EnvFile,
  type ExposureEntry,
  type Finding,
  type Report,
  type ScanContext,
  type ServiceSummary,
  type Severity,
  type SeverityCounts,
} from "./model";

const TOOL_NAME = "selfhosted-doctor";
const TOOL_VERSION = "0.3.0";

export interface ScanOptions {
  /** ISO timestamp to stamp on the report. Defaults to now. */
  generatedAt?: string;
  /** Compose profiles to treat as active (score-affecting). */
  profiles?: string[];
  /** Score every service, including all profile-gated ones. */
  allProfiles?: boolean;
}

/**
 * Build a scan context from parsed `docker inspect` containers (a running-stack
 * inventory). Feeds the SAME model the Compose parser produces, so rules /
 * scoring / verdict are unchanged. There are no env files or tunnels to discover
 * from a container inventory.
 */
export function buildContextFromContainers(
  containers: DockerInspectContainer[],
  target: string,
): ScanContext {
  const services = containersToServices(containers, target);
  return {
    target,
    files: [target],
    services,
    envFiles: [],
    tunnels: [],
  };
}

/**
 * Build the immutable scan context from an input path (file or directory).
 *
 * A file is auto-detected: if it is JSON shaped like `docker inspect` output
 * (an array of container objects) it is parsed as a running-container inventory;
 * otherwise it is parsed as Compose YAML as before. A directory always stays
 * Compose discovery.
 */
export function buildContext(inputPath: string): ScanContext {
  const containers = maybeLoadDockerInspectFile(inputPath);
  if (containers) {
    return buildContextFromContainers(containers, inputPath);
  }

  const { target, files } = loadInputs(inputPath);

  const services: ComposeService[] = [];
  const envFiles: EnvFile[] = [];
  const tunnels: CloudflareTunnel[] = [];

  for (const file of files) {
    if (file.kind === "compose") {
      services.push(...parseComposeServices(file));
    } else if (file.kind === "env") {
      envFiles.push(parseEnvFile(file));
    } else if (file.kind === "cloudflared") {
      const tunnel = parseCloudflaredConfig(file);
      if (tunnel) tunnels.push(tunnel);
    }
  }

  return {
    target,
    files: files.map((f) => f.path),
    services,
    envFiles,
    tunnels,
  };
}

function emptyCounts(): Record<Severity, number> {
  return { high: 0, medium: 0, low: 0, info: 0 };
}

/** Count findings by severity, with a total, for a report summary section. */
function countFindings(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = { high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
    counts.total += 1;
  }
  return counts;
}

function classificationOf(finding: Finding): Classification {
  return finding.classification ?? "active";
}

function buildExposure(services: ComposeService[], opts: ScanOptions = {}): ExposureEntry[] {
  const exposure: ExposureEntry[] = [];
  for (const service of services) {
    for (const port of service.ports) {
      if (!port.published) continue;
      const entry: ExposureEntry = {
        service: service.name,
        hostIp: port.hostIp && port.hostIp !== "" ? port.hostIp : "0.0.0.0",
        hostPort: port.hostPort && port.hostPort !== "" ? port.hostPort : port.containerPort,
        containerPort: port.containerPort,
        protocol: port.protocol,
        classification: "active",
      };
      if (!isServiceActive(service, opts)) {
        entry.classification = "conditional";
        entry.profiles = [...service.profiles];
      }
      exposure.push(entry);
    }
  }
  return exposure;
}

function buildServiceSummaries(
  services: ComposeService[],
  findings: Finding[],
): ServiceSummary[] {
  return services.map((service) => {
    const findingCounts = emptyCounts();
    for (const finding of findings) {
      if (finding.service === service.name) {
        findingCounts[finding.severity] += 1;
      }
    }
    const summary: ServiceSummary = {
      name: service.name,
      publishedPorts: service.ports.filter((p) => isPublicPort(p)).length,
      findingCounts,
    };
    if (service.image) summary.image = service.image;
    const detected = detectServiceType(service);
    if (detected) summary.detectedType = detected.id;
    return summary;
  });
}

/** Turn a scan context into a full Report. Exposed for tests. */
export function buildReport(ctx: ScanContext, opts: ScanOptions = {}): Report {
  const raw = runRules(ctx);
  const findings = classifyFindings(raw, ctx, {
    profiles: opts.profiles,
    allProfiles: opts.allProfiles,
  });

  const active = findings.filter((f) => classificationOf(f) === "active");
  const conditional = findings.filter((f) => classificationOf(f) === "conditional");
  const template = findings.filter((f) => classificationOf(f) === "template");

  // Score is driven by ACTIVE findings only.
  const { score, breakdown } = scoreActiveFindings(findings);

  return {
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    generatedAt: opts.generatedAt ?? new Date().toISOString(),
    target: ctx.target,
    files: ctx.files,
    summary: {
      riskScore: score,
      counts: countFindings(findings),
      active: countFindings(active),
      conditional: countFindings(conditional),
      template: countFindings(template),
      scoreBreakdown: breakdown,
    },
    findings,
    exposure: buildExposure(ctx.services, opts),
    services: buildServiceSummaries(ctx.services, findings),
  };
}

/** Scan a file or directory path and return a deterministic Report. */
export function scan(inputPath: string, opts: ScanOptions = {}): Report {
  const ctx = buildContext(inputPath);
  return buildReport(ctx, opts);
}

/**
 * Scan already-inspected containers (no Compose file) and return a deterministic
 * Report. Used by the `--running` path after the read-only Docker CLI collects
 * the inventory.
 */
export function scanContainers(
  containers: DockerInspectContainer[],
  target: string,
  opts: ScanOptions = {},
): Report {
  return buildReport(buildContextFromContainers(containers, target), opts);
}
