import { parse } from "yaml";
import type {
  LoadedFile,
  ComposeService,
  EnvFile,
  PortMapping,
  VolumeMount,
  EnvEntry,
} from "./model";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function coerceString(v: unknown): string {
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return "";
}

/** A value is a reference when it contains `${...}` or starts with `$`. */
function isReferenceValue(value: string): boolean {
  return value.includes("${") || value.startsWith("$");
}

export function parsePort(entry: unknown): PortMapping | undefined {
  // number form
  if (typeof entry === "number") {
    return {
      containerPort: String(entry),
      protocol: "tcp",
      published: true,
      raw: String(entry),
    };
  }

  // string short forms
  if (typeof entry === "string") {
    const raw = entry;
    let rest = entry.trim();
    if (rest === "") return undefined;

    // Split off /proto suffix first.
    let protocol = "tcp";
    const slashIdx = rest.lastIndexOf("/");
    if (slashIdx !== -1) {
      const proto = rest.slice(slashIdx + 1).trim().toLowerCase();
      if (proto === "tcp" || proto === "udp") {
        protocol = proto;
        rest = rest.slice(0, slashIdx);
      }
    }

    // Handle bracketed IPv6 host prefix: "[::]:8080:80"
    let hostIp: string | undefined;
    if (rest.startsWith("[")) {
      const close = rest.indexOf("]");
      if (close === -1) return undefined;
      hostIp = rest.slice(1, close);
      // Skip the "]" and an optional following ":"
      let after = rest.slice(close + 1);
      if (after.startsWith(":")) after = after.slice(1);
      rest = after;
    }

    const parts = rest.split(":");

    if (hostIp !== undefined) {
      // Already consumed host IP; remaining parts are [hostPort, containerPort] or [containerPort]
      if (parts.length === 2) {
        const hostPort = parts[0];
        const containerPort = parts[1];
        if (containerPort === undefined || containerPort === "") return undefined;
        return {
          hostIp,
          hostPort: hostPort === "" ? undefined : hostPort,
          containerPort,
          protocol,
          published: true,
          raw,
        };
      }
      if (parts.length === 1) {
        const containerPort = parts[0];
        if (containerPort === undefined || containerPort === "") return undefined;
        return { hostIp, containerPort, protocol, published: true, raw };
      }
      return undefined;
    }

    if (parts.length === 1) {
      // "80" -> containerPort only
      const containerPort = parts[0];
      if (containerPort === undefined || containerPort === "") return undefined;
      return { containerPort, protocol, published: true, raw };
    }
    if (parts.length === 2) {
      // "8080:80" -> hostPort:containerPort
      const hostPort = parts[0];
      const containerPort = parts[1];
      if (containerPort === undefined || containerPort === "") return undefined;
      return {
        hostPort: hostPort === "" ? undefined : hostPort,
        containerPort,
        protocol,
        published: true,
        raw,
      };
    }
    if (parts.length === 3) {
      // "127.0.0.1:8080:80" -> hostIp:hostPort:containerPort
      const ip = parts[0];
      const hostPort = parts[1];
      const containerPort = parts[2];
      if (containerPort === undefined || containerPort === "") return undefined;
      return {
        hostIp: ip === "" ? undefined : ip,
        hostPort: hostPort === "" ? undefined : hostPort,
        containerPort,
        protocol,
        published: true,
        raw,
      };
    }
    return undefined;
  }

  // long object form
  if (isRecord(entry)) {
    const target = entry["target"];
    if (target === undefined || target === null) return undefined;
    const containerPort = coerceString(target);
    if (containerPort === "") return undefined;

    const publishedVal = entry["published"];
    const hostPort =
      publishedVal !== undefined && publishedVal !== null ? coerceString(publishedVal) : undefined;

    const hostIpVal = entry["host_ip"];
    const hostIp =
      typeof hostIpVal === "string" && hostIpVal !== "" ? hostIpVal : undefined;

    const protoVal = entry["protocol"];
    const protocol = typeof protoVal === "string" && protoVal !== "" ? protoVal : "tcp";

    const rawParts: string[] = [];
    if (hostIp !== undefined) rawParts.push(hostIp);
    if (hostPort !== undefined) rawParts.push(hostPort);
    rawParts.push(containerPort);
    let raw = rawParts.join(":");
    if (protocol !== "tcp") raw = `${raw}/${protocol}`;

    return { hostIp, hostPort, containerPort, protocol, published: true, raw };
  }

  return undefined;
}

function parseVolume(entry: unknown): VolumeMount | undefined {
  if (typeof entry === "string") {
    const raw = entry;
    // src:dst[:ro] — but beware Windows drive letters / options; keep simple.
    const parts = entry.split(":");
    if (parts.length === 1) {
      // Anonymous or named-only volume "dst"
      const target = parts[0];
      return { raw, target: target === "" ? undefined : target, readOnly: false };
    }
    // Last part may be an access mode (ro/rw or others).
    const last = parts[parts.length - 1];
    let readOnly = false;
    let effective = parts;
    if (last === "ro" || last === "rw") {
      readOnly = last === "ro";
      effective = parts.slice(0, -1);
    }
    const source = effective[0];
    const target = effective[1];
    return {
      raw,
      source: source === undefined || source === "" ? undefined : source,
      target: target === undefined || target === "" ? undefined : target,
      readOnly,
    };
  }

  if (isRecord(entry)) {
    const sourceVal = entry["source"];
    const targetVal = entry["target"];
    const source = typeof sourceVal === "string" ? sourceVal : undefined;
    const target = typeof targetVal === "string" ? targetVal : undefined;
    const readOnly = entry["read_only"] === true;
    const raw = `${source ?? ""}:${target ?? ""}`;
    return { raw, source, target, readOnly };
  }

  return undefined;
}

function parseEnvironment(env: unknown): EnvEntry[] {
  const entries: EnvEntry[] = [];
  if (Array.isArray(env)) {
    for (const item of env) {
      const s = coerceString(item);
      const eqIdx = s.indexOf("=");
      if (eqIdx === -1) {
        entries.push({ key: s.trim(), value: "", isReference: false });
      } else {
        const key = s.slice(0, eqIdx).trim();
        const value = s.slice(eqIdx + 1);
        entries.push({ key, value, isReference: isReferenceValue(value) });
      }
    }
  } else if (isRecord(env)) {
    for (const key of Object.keys(env)) {
      const value = coerceString(env[key]);
      entries.push({ key, value, isReference: isReferenceValue(value) });
    }
  }
  return entries;
}

function parseExpose(expose: unknown): string[] {
  if (!Array.isArray(expose)) return [];
  const out: string[] = [];
  for (const item of expose) {
    if (typeof item === "string") out.push(item);
    else if (typeof item === "number") out.push(String(item));
  }
  return out;
}

function parseLabels(labels: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (Array.isArray(labels)) {
    for (const item of labels) {
      const s = coerceString(item);
      const eqIdx = s.indexOf("=");
      if (eqIdx === -1) {
        out[s.trim()] = "";
      } else {
        out[s.slice(0, eqIdx).trim()] = s.slice(eqIdx + 1);
      }
    }
  } else if (isRecord(labels)) {
    for (const key of Object.keys(labels)) {
      out[key] = coerceString(labels[key]);
    }
  }
  return out;
}

function computeHealthcheck(node: Record<string, unknown>): {
  hasHealthcheck: boolean;
  healthcheckDisabled: boolean;
} {
  if (!("healthcheck" in node)) {
    return { hasHealthcheck: false, healthcheckDisabled: false };
  }
  const hc = node["healthcheck"];
  if (!isRecord(hc)) {
    // Present but not an object; treat as present, not disabled.
    return { hasHealthcheck: true, healthcheckDisabled: false };
  }
  let disabled = hc["disable"] === true;
  const test = hc["test"];
  if (typeof test === "string" && test === "NONE") disabled = true;
  if (Array.isArray(test) && test.length === 1 && test[0] === "NONE") disabled = true;
  return { hasHealthcheck: !disabled, healthcheckDisabled: disabled };
}

function computeResourceLimits(node: Record<string, unknown>): boolean {
  if ("mem_limit" in node || "cpus" in node || "cpu_shares" in node) return true;
  const deploy = node["deploy"];
  if (isRecord(deploy)) {
    const resources = deploy["resources"];
    if (isRecord(resources)) {
      const limits = resources["limits"];
      if (limits !== undefined && limits !== null) return true;
    }
  }
  return false;
}

export function parseComposeServices(file: LoadedFile): ComposeService[] {
  let doc: unknown;
  try {
    doc = parse(file.content);
  } catch {
    return [];
  }
  if (!isRecord(doc)) return [];
  const services = doc["services"];
  if (!isRecord(services)) return [];

  const result: ComposeService[] = [];

  for (const name of Object.keys(services)) {
    const rawNode = services[name];
    const node: Record<string, unknown> = isRecord(rawNode) ? rawNode : {};

    const imageVal = node["image"];
    const image = typeof imageVal === "string" ? imageVal : undefined;

    const containerNameVal = node["container_name"];
    const containerName =
      typeof containerNameVal === "string" ? containerNameVal : undefined;

    const networkModeVal = node["network_mode"];
    const networkMode =
      typeof networkModeVal === "string" ? networkModeVal : undefined;

    const restartVal = node["restart"];
    const restart = typeof restartVal === "string" ? restartVal : undefined;

    const userVal = node["user"];
    const user =
      typeof userVal === "string"
        ? userVal
        : typeof userVal === "number"
          ? String(userVal)
          : undefined;

    const privileged = node["privileged"] === true;

    // ports
    const ports: PortMapping[] = [];
    const portsVal = node["ports"];
    if (Array.isArray(portsVal)) {
      for (const p of portsVal) {
        const mapped = parsePort(p);
        if (mapped) ports.push(mapped);
      }
    }

    const expose = parseExpose(node["expose"]);

    // volumes
    const volumes: VolumeMount[] = [];
    const volumesVal = node["volumes"];
    if (Array.isArray(volumesVal)) {
      for (const v of volumesVal) {
        const mv = parseVolume(v);
        if (mv) volumes.push(mv);
      }
    }

    const environment = parseEnvironment(node["environment"]);
    const { hasHealthcheck, healthcheckDisabled } = computeHealthcheck(node);
    const labels = parseLabels(node["labels"]);
    const hasResourceLimits = computeResourceLimits(node);

    result.push({
      name,
      image,
      containerName,
      privileged,
      networkMode,
      ports,
      expose,
      volumes,
      environment,
      hasHealthcheck,
      healthcheckDisabled,
      restart,
      user,
      labels,
      hasResourceLimits,
      file: file.path,
      raw: node,
    });
  }

  return result;
}

export function parseEnvFile(file: LoadedFile): EnvFile {
  const entries: EnvEntry[] = [];
  const lines = file.content.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    if (trimmed.startsWith("#")) continue;

    let working = trimmed;
    if (working.startsWith("export ")) {
      working = working.slice("export ".length).trimStart();
    }

    const eqIdx = working.indexOf("=");
    if (eqIdx === -1) {
      // A bare key with no value.
      entries.push({ key: working.trim(), value: "", isReference: false });
      continue;
    }

    const key = working.slice(0, eqIdx).trim();
    let value = working.slice(eqIdx + 1).trim();

    // Strip a single pair of surrounding single or double quotes.
    if (value.length >= 2) {
      const first = value[0];
      const last = value[value.length - 1];
      if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
        value = value.slice(1, -1);
      }
    }

    entries.push({ key, value, isReference: isReferenceValue(value) });
  }
  return { path: file.path, entries };
}
