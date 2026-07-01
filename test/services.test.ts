import { describe, it, expect } from "vitest";
import { detectServiceType, isDatabaseService, SERVICE_CATALOG } from "../src/core/services";
import { parseComposeServices } from "../src/core/compose";
import type { LoadedFile } from "../src/core/model";

function svc(yaml: string) {
  const loaded: LoadedFile = { path: "c.yml", kind: "compose", content: yaml };
  return parseComposeServices(loaded)[0]!;
}

describe("detectServiceType", () => {
  it("detects by image", () => {
    expect(detectServiceType(svc(`services:\n  x:\n    image: vaultwarden/server:latest\n`))?.id).toBe("vaultwarden");
    expect(detectServiceType(svc(`services:\n  x:\n    image: ghcr.io/immich-app/immich-server:release\n`))?.id).toBe("immich");
    expect(detectServiceType(svc(`services:\n  x:\n    image: cloudflare/cloudflared:latest\n`))?.id).toBe("cloudflared");
  });

  it("prefers image over a prefixed container_name (nextcloud_db running mariadb is a database)", () => {
    const s = svc(`services:\n  db:\n    image: mariadb:10.11\n    container_name: nextcloud_db\n`);
    expect(detectServiceType(s)?.id).toBe("mariadb");
  });

  it("falls back to service name when no image matches", () => {
    expect(detectServiceType(svc(`services:\n  jellyfin:\n    image: custom/fork:1\n`))?.id).toBe("jellyfin");
  });

  it("covers at least 10 well-known services", () => {
    expect(SERVICE_CATALOG.length).toBeGreaterThanOrEqual(10);
  });
});

describe("isDatabaseService", () => {
  it("treats postgres/mysql/mariadb/mongo/redis as databases for exposure", () => {
    for (const img of ["postgres:16", "mysql:8", "mariadb:10.11", "mongo:7", "redis:7"]) {
      expect(isDatabaseService(svc(`services:\n  d:\n    image: ${img}\n`))).toBe(true);
    }
  });

  it("does not treat an app as a database", () => {
    expect(isDatabaseService(svc(`services:\n  a:\n    image: nextcloud:latest\n`))).toBe(false);
  });
});
