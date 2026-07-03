/**
 * `docker inspect` → normalized model adapter.
 *
 * `docker inspect $(docker ps -q)` emits a JSON ARRAY of container objects. This
 * module turns that array — whether read from a file or produced by the local
 * Docker CLI (see docker-cli.ts) — into the SAME `ComposeService[]` the Compose
 * parser produces, so the existing rules / scanner / verdict run over already
 * running containers with no changes.
 *
 * It is 100% read-only: it only ever *reads* container configuration. The env
 * values here are the real, resolved running values (actual live secrets), so —
 * exactly like Compose env — they flow through the existing secret detection and
 * are redacted via `redactValue` before anything is displayed. There is no
 * Compose `profiles:` concept for a running container, so every container maps
 * to an always-active service.
 */
import fs from "node:fs";
import type { ComposeService, EnvEntry, PortMapping, VolumeMount } from "./model";
import { makeEnvEntry } from "./compose";

/** One host binding for a container port, e.g. `{ HostIp: "0.0.0.0", HostPort: "5432" }`. */
interface DockerPortBinding {
  HostIp?: string;
  HostPort?: string;
}

/** Map of `"<port>/<proto>"` → published host bindings (null when only exposed). */
type PortBindingMap = Record<string, DockerPortBinding[] | null>;

/** One resolved mount from a container's `Mounts` array. */
interface DockerMount {
  Type?: string;
  Source?: string;
  Destination?: string;
  Mode?: string;
  RW?: boolean;
}

/**
 * The subset of a `docker inspect` container object we read. Everything is
 * optional: real `docker inspect` output always has these keys, but we never
 * assume — a missing field just maps to a safe default.
 */
export interface DockerInspectContainer {
  Id?: string;
  Name?: string;
  Config?: {
    Image?: string;
    Env?: string[] | null;
    User?: string;
    Healthcheck?: unknown;
    Labels?: Record<string, string> | null;
  } | null;
  HostConfig?: {
    Privileged?: boolean;
    NetworkMode?: string;
    RestartPolicy?: { Name?: string } | null;
    PortBindings?: PortBindingMap | null;
    Binds?: string[] | null;
    Memory?: number;
    NanoCpus?: number;
    CpuShares?: number;
  } | null;
  Mounts?: DockerMount[] | null;
  NetworkSettings?: {
    Ports?: PortBindingMap | null;
  } | null;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * True when a parsed JSON value looks like `docker inspect` output: a non-empty
 * array whose first element is an object carrying container-shaped keys (`Id`
 * plus `Config` and/or `HostConfig`). Deliberately strict so a random JSON array
 * is never misread as containers — it falls through to Compose parsing instead.
 */
export function looksLikeDockerInspect(value: unknown): value is DockerInspectContainer[] {
  if (!Array.isArray(value) || value.length === 0) return false;
  const first = value[0];
  if (!isRecord(first)) return false;
  return "Id" in first && ("Config" in first || "HostConfig" in first);
}

/** Parse JSON text and return containers ONLY if it is docker-inspect-shaped, else null. */
export function parseDockerInspectText(text: string): DockerInspectContainer[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  return looksLikeDockerInspect(parsed) ? parsed : null;
}

/**
 * If `inputPath` is a FILE holding docker-inspect JSON, read + parse it; else
 * return null so the caller falls back to Compose loading. Directories are never
 * treated as docker-inspect input — they stay Compose discovery as before.
 */
export function maybeLoadDockerInspectFile(inputPath: string): DockerInspectContainer[] | null {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(inputPath);
  } catch {
    return null;
  }
  if (!stat.isFile()) return null;
  let content: string;
  try {
    content = fs.readFileSync(inputPath, "utf8");
  } catch {
    return null;
  }
  return parseDockerInspectText(content);
}

/** Strip Docker's leading "/" from a container name; fall back when absent. */
function cleanName(name: string | undefined, fallback: string): string {
  if (typeof name === "string" && name.length > 0) {
    return name.startsWith("/") ? name.slice(1) : name;
  }
  return fallback;
}

/** Split a `"5432/tcp"` port key into its container port and protocol. */
function splitPortKey(key: string): { containerPort: string; protocol: string } {
  const slash = key.lastIndexOf("/");
  if (slash === -1) return { containerPort: key, protocol: "tcp" };
  const proto = key.slice(slash + 1).toLowerCase();
  return { containerPort: key.slice(0, slash), protocol: proto === "udp" ? "udp" : "tcp" };
}

/**
 * Turn a Docker PortBindings / NetworkSettings.Ports map into normalized port
 * mappings. A key with a non-empty binding array is PUBLISHED to the host; a key
 * with a null/empty array is merely exposed internally (goes to `expose`).
 *
 * `HostIp` of "" or "0.0.0.0" (or "::") means published to all interfaces
 * (public); "127.0.0.1" / "::1" means loopback-only — this matches the existing
 * `isPublicPort` semantics, so an empty HostIp maps to `undefined` (treated as
 * public), while a loopback IP is preserved and correctly seen as private.
 */
function portsFromBindings(map: PortBindingMap | null | undefined): {
  ports: PortMapping[];
  exposed: string[];
} {
  const ports: PortMapping[] = [];
  const exposed: string[] = [];
  if (!isRecord(map)) return { ports, exposed };

  for (const key of Object.keys(map)) {
    const { containerPort, protocol } = splitPortKey(key);
    if (containerPort === "") continue;
    const bindings = map[key];
    if (Array.isArray(bindings) && bindings.length > 0) {
      for (const b of bindings) {
        const rawIp = typeof b?.HostIp === "string" ? b.HostIp : "";
        const hostIp = rawIp === "" ? undefined : rawIp;
        const hostPort =
          typeof b?.HostPort === "string" && b.HostPort !== "" ? b.HostPort : undefined;
        const port: PortMapping = {
          raw: `${hostIp ?? "0.0.0.0"}:${hostPort ?? containerPort}->${containerPort}/${protocol}`,
          containerPort,
          protocol,
          published: true,
        };
        if (hostIp !== undefined) port.hostIp = hostIp;
        if (hostPort !== undefined) port.hostPort = hostPort;
        ports.push(port);
      }
    } else {
      exposed.push(protocol === "tcp" ? containerPort : `${containerPort}/${protocol}`);
    }
  }
  return { ports, exposed };
}

/** Parse `Config.Env` (["KEY=VALUE", …]) into normalized env entries. */
function envFromConfig(env: string[] | null | undefined): EnvEntry[] {
  const entries: EnvEntry[] = [];
  if (!Array.isArray(env)) return entries;
  for (const item of env) {
    if (typeof item !== "string") continue;
    const eq = item.indexOf("=");
    if (eq === -1) {
      entries.push({ key: item.trim(), value: "", isReference: false });
    } else {
      entries.push(makeEnvEntry(item.slice(0, eq).trim(), item.slice(eq + 1)));
    }
  }
  return entries;
}

/**
 * Build normalized volume mounts from a container. Prefers the resolved `Mounts`
 * array (authoritative), falling back to `HostConfig.Binds` strings. The
 * docker-socket rule keys off `source`, so when a mount's `Source` is empty
 * (e.g. a named volume) we fall back to its `Destination` for detection.
 */
function volumesFromContainer(c: DockerInspectContainer): VolumeMount[] {
  const volumes: VolumeMount[] = [];
  const mounts = c.Mounts;
  if (Array.isArray(mounts)) {
    for (const m of mounts) {
      if (!isRecord(m)) continue;
      const src = typeof m.Source === "string" && m.Source !== "" ? m.Source : undefined;
      const dst =
        typeof m.Destination === "string" && m.Destination !== "" ? m.Destination : undefined;
      const source = src ?? dst;
      const mount: VolumeMount = { raw: `${src ?? ""}:${dst ?? ""}`, readOnly: m.RW === false };
      if (source !== undefined) mount.source = source;
      if (dst !== undefined) mount.target = dst;
      volumes.push(mount);
    }
    return volumes;
  }

  const binds = c.HostConfig?.Binds;
  if (Array.isArray(binds)) {
    for (const bind of binds) {
      if (typeof bind !== "string") continue;
      const parts = bind.split(":");
      const source = parts[0] && parts[0] !== "" ? parts[0] : undefined;
      const target = parts[1] && parts[1] !== "" ? parts[1] : undefined;
      const mode = parts[2];
      const mount: VolumeMount = { raw: bind, readOnly: mode === "ro" };
      if (source !== undefined) mount.source = source;
      if (target !== undefined) mount.target = target;
      volumes.push(mount);
    }
  }
  return volumes;
}

/** Derive healthcheck presence from `Config.Healthcheck` (Test ["NONE"] = disabled). */
function healthcheckFromConfig(config: NonNullable<DockerInspectContainer["Config"]>): {
  hasHealthcheck: boolean;
  healthcheckDisabled: boolean;
} {
  const hc = config.Healthcheck;
  if (!isRecord(hc)) return { hasHealthcheck: false, healthcheckDisabled: false };
  const test = hc["Test"];
  const disabled = Array.isArray(test) && test.length >= 1 && test[0] === "NONE";
  return { hasHealthcheck: !disabled, healthcheckDisabled: disabled };
}

/** Map a single inspected container onto the normalized ComposeService model. */
export function containerToService(c: DockerInspectContainer, file: string): ComposeService {
  const config = c.Config ?? {};
  const host = c.HostConfig ?? {};

  const fallbackName =
    typeof c.Id === "string" && c.Id.length >= 12 ? c.Id.slice(0, 12) : "container";
  const name = cleanName(c.Name, fallbackName);

  const image = typeof config.Image === "string" && config.Image !== "" ? config.Image : undefined;
  const networkMode = typeof host.NetworkMode === "string" ? host.NetworkMode : undefined;
  const privileged = host.Privileged === true;

  const restartName = host.RestartPolicy?.Name;
  const restart =
    typeof restartName === "string" && restartName !== "" ? restartName : undefined;

  const userVal = config.User;
  const user = typeof userVal === "string" && userVal !== "" ? userVal : undefined;

  // Prefer explicit host PortBindings; fall back to NetworkSettings.Ports.
  let { ports, exposed } = portsFromBindings(host.PortBindings);
  if (ports.length === 0) {
    const fallback = portsFromBindings(c.NetworkSettings?.Ports);
    ports = fallback.ports;
    if (exposed.length === 0) exposed = fallback.exposed;
  }

  const environment = envFromConfig(config.Env);
  const volumes = volumesFromContainer(c);
  const { hasHealthcheck, healthcheckDisabled } = healthcheckFromConfig(config);

  const labels: Record<string, string> = {};
  if (isRecord(config.Labels)) {
    for (const k of Object.keys(config.Labels)) {
      const v = (config.Labels as Record<string, unknown>)[k];
      labels[k] = typeof v === "string" ? v : String(v);
    }
  }

  const hasResourceLimits =
    (host.Memory ?? 0) > 0 || (host.NanoCpus ?? 0) > 0 || (host.CpuShares ?? 0) > 0;

  return {
    name,
    image,
    containerName: name,
    privileged,
    networkMode,
    ports,
    expose: exposed,
    // Running containers are always active — there is no Compose profile gate.
    profiles: [],
    volumes,
    environment,
    hasHealthcheck,
    healthcheckDisabled,
    restart,
    user,
    labels,
    hasResourceLimits,
    file,
    raw: c as unknown as Record<string, unknown>,
  };
}

/** Map an array of inspected containers onto normalized services. */
export function containersToServices(
  containers: DockerInspectContainer[],
  file: string,
): ComposeService[] {
  return containers.map((c) => containerToService(c, file));
}
