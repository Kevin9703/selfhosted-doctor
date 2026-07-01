import type { PortMapping } from "../model";

export interface ImageRef {
  name: string;
  tag?: string;
  digest?: string;
}

/**
 * Parse an image reference like "ghcr.io/u/app:1.2@sha256:...".
 *
 * Handles:
 *  - a registry host that itself contains a port (a colon that appears before a
 *    '/'), which must NOT be treated as the tag separator;
 *  - a missing tag (=> tag undefined);
 *  - a digest introduced by '@'.
 */
export function parseImageRef(image: string): ImageRef {
  const trimmed = image.trim();

  let rest = trimmed;
  let digest: string | undefined;

  const atIndex = rest.indexOf("@");
  if (atIndex >= 0) {
    digest = rest.slice(atIndex + 1) || undefined;
    rest = rest.slice(0, atIndex);
  }

  // Determine whether a ':' is a tag separator. The tag ':' must come AFTER the
  // last '/'. A ':' before a '/' (or with no '/' after it) is a registry port.
  let tag: string | undefined;
  const lastColon = rest.lastIndexOf(":");
  const lastSlash = rest.lastIndexOf("/");
  if (lastColon > lastSlash) {
    tag = rest.slice(lastColon + 1) || undefined;
    rest = rest.slice(0, lastColon);
  }

  return { name: rest, tag, digest };
}

/**
 * A published port that binds a PUBLIC interface: it is published AND its host
 * interface is either unspecified, "0.0.0.0", or "::". Loopback (127.0.0.1,
 * ::1) and specific private IPs are NOT public.
 */
export function isPublicPort(port: PortMapping): boolean {
  if (!port.published) {
    return false;
  }
  const hostIp = port.hostIp;
  if (hostIp === undefined || hostIp === "" || hostIp === "0.0.0.0" || hostIp === "::") {
    return true;
  }
  return false;
}

/** Return the default inside a full Compose parameter expansion: ${VAR:-8080}. */
export function composeDefault(value: string): string | undefined {
  const match = value.match(/^\$\{[^}:]+(?::-|-)([^}]+)\}$/);
  return match?.[1];
}

/**
 * Best-effort display/effective port for rules. Keeps literal ports unchanged
 * and resolves whole-value Compose defaults such as `${PORT:-80}` to `80`.
 */
export function effectivePort(value: string): string {
  return composeDefault(value) ?? value;
}

/**
 * Format a port for evidence, e.g. "0.0.0.0:8080->80/tcp". Uses "0.0.0.0" when
 * the host interface is not specified.
 */
export function formatPort(port: PortMapping): string {
  const hostIp = port.hostIp && port.hostIp !== "" ? port.hostIp : "0.0.0.0";
  const hostPort = port.hostPort && port.hostPort !== "" ? port.hostPort : port.containerPort;
  return `${hostIp}:${hostPort}->${port.containerPort}/${port.protocol}`;
}
