/**
 * Well-known self-hosted service catalog, detection, and service-specific notes.
 *
 * `detectServiceType` matches a normalized ComposeService against the catalog by
 * case-insensitive substring on name / container_name / image. The catalog is
 * ordered so that more specific ids win (e.g. "mariadb" before generic entries).
 */

import type { ComposeService, Severity } from "./model";

export type ServiceCategory =
  | "password-manager" | "media" | "photos" | "cloud"
  | "automation" | "git" | "database" | "cache" | "proxy" | "tunnel" | "other";

export interface ServiceDefinition {
  id: string;            // canonical id, e.g. "vaultwarden"
  label: string;         // display name, e.g. "Vaultwarden"
  category: ServiceCategory;
  match: { names?: string[]; images?: string[] }; // case-insensitive substrings
  isDatabase?: boolean;
  /** True for sensitive apps where direct public exposure is especially risky. */
  sensitive?: boolean;
}

/**
 * Ordered most-specific first. Detection walks this list in order and returns
 * the first match, so more specific database ids (mariadb) precede any entry
 * that could shadow them.
 */
export const SERVICE_CATALOG: ServiceDefinition[] = [
  // Password managers (sensitive)
  {
    id: "vaultwarden",
    label: "Vaultwarden",
    category: "password-manager",
    sensitive: true,
    match: {
      names: ["vaultwarden", "bitwarden_rs", "bitwardenrs"],
      images: ["vaultwarden", "bitwardenrs/server"],
    },
  },
  {
    id: "bitwarden",
    label: "Bitwarden",
    category: "password-manager",
    sensitive: true,
    match: {
      names: ["bitwarden"],
      images: ["bitwarden"],
    },
  },

  // Apps
  {
    id: "nextcloud",
    label: "Nextcloud",
    category: "cloud",
    match: {
      names: ["nextcloud"],
      images: ["nextcloud"],
    },
  },
  {
    id: "immich",
    label: "Immich",
    category: "photos",
    match: {
      names: ["immich"],
      images: ["immich", "ghcr.io/immich-app"],
    },
  },
  {
    id: "jellyfin",
    label: "Jellyfin",
    category: "media",
    match: {
      names: ["jellyfin"],
      images: ["jellyfin"],
    },
  },
  {
    id: "homeassistant",
    label: "Home Assistant",
    category: "automation",
    match: {
      names: ["homeassistant", "home-assistant", "hass"],
      images: ["homeassistant"],
    },
  },
  {
    id: "gitea",
    label: "Gitea",
    category: "git",
    match: {
      names: ["gitea"],
      images: ["gitea"],
    },
  },

  // Databases — most specific first so "mariadb" wins over "mysql", etc.
  {
    id: "mariadb",
    label: "MariaDB",
    category: "database",
    isDatabase: true,
    match: {
      names: ["mariadb"],
      images: ["mariadb"],
    },
  },
  {
    id: "postgres",
    label: "PostgreSQL",
    category: "database",
    isDatabase: true,
    match: {
      names: ["postgres", "postgresql", "pgvecto", "pgvector"],
      images: ["postgres", "postgresql", "pgvecto", "pgvector"],
    },
  },
  {
    id: "mysql",
    label: "MySQL",
    category: "database",
    isDatabase: true,
    match: {
      names: ["mysql"],
      images: ["mysql"],
    },
  },
  {
    id: "mongodb",
    label: "MongoDB",
    category: "database",
    isDatabase: true,
    match: {
      names: ["mongodb", "mongo"],
      images: ["mongo"],
    },
  },
  {
    id: "redis",
    label: "Redis",
    category: "cache",
    isDatabase: false,
    match: {
      names: ["redis"],
      images: ["redis"],
    },
  },

  // Proxies / tunnels
  {
    id: "traefik",
    label: "Traefik",
    category: "proxy",
    match: {
      names: ["traefik"],
      images: ["traefik"],
    },
  },
  {
    id: "nginx",
    label: "Nginx",
    category: "proxy",
    match: {
      names: ["nginx", "swag", "nginx-proxy-manager", "npm"],
      images: ["nginx", "swag", "nginx-proxy-manager", "jc21/nginx-proxy-manager"],
    },
  },
  {
    id: "caddy",
    label: "Caddy",
    category: "proxy",
    match: {
      names: ["caddy"],
      images: ["caddy"],
    },
  },
  {
    id: "cloudflared",
    label: "Cloudflare Tunnel",
    category: "tunnel",
    match: {
      names: ["cloudflared", "cloudflare-tunnel"],
      images: ["cloudflare/cloudflared"],
    },
  },
];

/** Lower-cased haystacks (name, container_name, image) for a service. */
function serviceHaystacks(service: ComposeService): {
  names: string[];
  image: string;
} {
  const names: string[] = [service.name.toLowerCase()];
  if (service.containerName) {
    names.push(service.containerName.toLowerCase());
  }
  const image = service.image ? service.image.toLowerCase() : "";
  return { names, image };
}

function imageMatches(def: ServiceDefinition, image: string): boolean {
  if (image.length === 0) return false;
  for (const needle of def.match.images ?? []) {
    if (image.includes(needle.toLowerCase())) return true;
  }
  return false;
}

function nameMatches(def: ServiceDefinition, names: string[]): boolean {
  for (const needle of def.match.names ?? []) {
    const n = needle.toLowerCase();
    for (const hay of names) {
      if (hay.includes(n)) return true;
    }
  }
  return false;
}

/**
 * Detect a well-known service by matching image, then name / container_name
 * (all case-insensitive substring).
 *
 * Image is checked FIRST across the whole catalog because it is the most
 * reliable signal: a service named `nextcloud_db` running the `mariadb` image is
 * a database, not Nextcloud. Container names are frequently prefixed with the
 * stack name, so name matching is only a fallback when no image matches.
 */
export function detectServiceType(
  service: ComposeService,
): ServiceDefinition | undefined {
  const { names, image } = serviceHaystacks(service);

  for (const def of SERVICE_CATALOG) {
    if (imageMatches(def, image)) return def;
  }
  for (const def of SERVICE_CATALOG) {
    if (nameMatches(def, names)) return def;
  }
  return undefined;
}

/**
 * Keywords that clearly identify a database engine even when the service isn't
 * an exact catalog match. Redis is intentionally included: an exposed Redis is
 * high-risk, so we treat it as a database for exposure purposes.
 */
const DB_KEYWORDS: string[] = [
  "postgres",
  "postgresql",
  "pgvecto",
  "pgvector",
  "mysql",
  "mariadb",
  "mongo",
  "redis",
  "couchdb",
  "influxdb",
];

/** True when the service is a database (detected def.isDatabase, or clearly a known DB). */
export function isDatabaseService(service: ComposeService): boolean {
  const def = detectServiceType(service);
  if (def) {
    // Redis is catalogued as isDatabase:false but is still a sensitive data
    // store — an exposed Redis is high-risk, so treat it as a database here.
    if (def.category === "cache") {
      return true;
    }
    if (def.isDatabase) {
      return true;
    }
  }

  const { names, image } = serviceHaystacks(service);
  for (const keyword of DB_KEYWORDS) {
    if (image.includes(keyword)) {
      return true;
    }
    for (const hay of names) {
      if (hay.includes(keyword)) {
        return true;
      }
    }
  }

  return false;
}

export interface ServiceNoteRule {
  serviceId: string;      // matches ServiceDefinition.id
  severity: Severity;
  title: string;
  detail: string;
  recommendation: string;
  /**
   * "always"     -> always emit for a detected service
   * "exposed"    -> emit only if THIS service publishes a public host port
   * "db-exposed" -> emit only if ANY database service in the stack publishes a public host port
   */
  when: "always" | "exposed" | "db-exposed";
}

export const SERVICE_NOTES: ServiceNoteRule[] = [
  {
    serviceId: "vaultwarden",
    severity: "high",
    when: "exposed",
    title: "Vaultwarden is directly exposed to the network",
    detail:
      "A publicly reachable password manager is a prime target for attackers: it holds every credential you own, so any exposed port invites brute-force and exploit attempts.",
    recommendation:
      "Put Vaultwarden behind Cloudflare Access, a VPN (e.g. WireGuard/Tailscale), or a reverse proxy that enforces strong authentication instead of publishing it directly.",
  },
  {
    serviceId: "immich",
    severity: "high",
    when: "db-exposed",
    title: "Immich database is exposed on the network",
    detail:
      "The Postgres database backing Immich publishes a public host port. An exposed database gives attackers a direct path to all photo metadata and stored credentials.",
    recommendation:
      "Bind the database to localhost only (e.g. 127.0.0.1:5432:5432) or drop the host port entirely so only Immich reaches it over the internal network.",
  },
  {
    serviceId: "immich",
    severity: "low",
    when: "always",
    title: "Back up both the Immich library and its database",
    detail:
      "Immich stores photos on a volume and all metadata/albums in Postgres. A backup of only one of the two cannot restore your library.",
    recommendation:
      "Back up the photo library volume AND the Postgres database volume together so a restore is complete and consistent.",
  },
  {
    serviceId: "nextcloud",
    severity: "high",
    when: "db-exposed",
    title: "Nextcloud database is exposed on the network",
    detail:
      "The database backing Nextcloud publishes a public host port, giving attackers a direct path to your files' metadata and account data.",
    recommendation:
      "Bind the database to localhost only (e.g. 127.0.0.1:3306:3306) or remove the host port so only Nextcloud reaches it over the internal network.",
  },
  {
    serviceId: "nextcloud",
    severity: "low",
    when: "always",
    title: "Configure trusted domains and proxy settings for Nextcloud",
    detail:
      "Behind a reverse proxy, Nextcloud needs to know its external hostname and scheme, otherwise links break and requests may be rejected as untrusted.",
    recommendation:
      "Set `trusted_domains` and `overwriteprotocol` (plus `overwrite.cli.url`/`trusted_proxies` as needed) so Nextcloud generates correct URLs behind the proxy.",
  },
  {
    serviceId: "jellyfin",
    severity: "medium",
    when: "exposed",
    title: "Jellyfin is directly exposed to the network",
    detail:
      "Jellyfin publishes a public host port. A directly exposed media server with a weak or default admin account is an easy account-takeover target.",
    recommendation:
      "Secure the admin account with strong, unique credentials and consider placing Jellyfin behind a reverse proxy or VPN rather than exposing it directly.",
  },
];
