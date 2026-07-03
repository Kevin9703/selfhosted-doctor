import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import {
  containersToServices,
  looksLikeDockerInspect,
  parseDockerInspectText,
  type DockerInspectContainer,
} from "../src/core/docker-inspect";
import { scan, scanContainers, buildContextFromContainers } from "../src/core/scanner";
import { assessExposure } from "../src/core/verdict";
import { renderExpose } from "../src/report/expose";
import type { Report } from "../src/core/model";

const STAMP = { generatedAt: "2026-07-01T00:00:00.000Z" };

/** The literal running secret planted in the exposed-db fixture. */
const REAL_SECRET = "hunter2superSecret";

/** Fixtures are resolved relative to the repo root (vitest cwd), like other tests. */
function fixturePath(name: string): string {
  return `test/fixtures/docker-inspect/${name}.json`;
}

function loadContainers(name: string): DockerInspectContainer[] {
  const parsed = parseDockerInspectText(readFileSync(fixturePath(name), "utf8"));
  if (!parsed) throw new Error(`fixture ${name} is not docker-inspect-shaped`);
  return parsed;
}

const ruleIds = (report: Report): Set<string> => new Set(report.findings.map((f) => f.ruleId));

describe("docker-inspect detection", () => {
  it("recognizes a docker-inspect array (Id + Config/HostConfig)", () => {
    expect(looksLikeDockerInspect(loadContainers("exposed-db"))).toBe(true);
  });

  it("rejects non-container JSON so it falls through to Compose parsing", () => {
    expect(looksLikeDockerInspect([])).toBe(false);
    expect(looksLikeDockerInspect([{ services: {} }])).toBe(false);
    expect(looksLikeDockerInspect({ services: { app: {} } })).toBe(false);
    expect(parseDockerInspectText("services:\n  app:\n    image: nginx")).toBeNull();
  });
});

describe("container → model mapping", () => {
  it("maps name, image, published public port, and resolved env secret", () => {
    const [db] = containersToServices(loadContainers("exposed-db"), "exposed-db.json");
    expect(db).toBeDefined();
    expect(db!.name).toBe("sdtest-db"); // leading "/" stripped
    expect(db!.image).toBe("postgres:16-alpine");
    expect(db!.profiles).toEqual([]); // running containers are always active

    // 5432 published on 0.0.0.0 → public.
    const pub = db!.ports.find((p) => p.containerPort === "5432");
    expect(pub).toBeDefined();
    expect(pub!.published).toBe(true);
    expect(pub!.hostIp).toBe("0.0.0.0");
    expect(pub!.hostPort).toBe("5432");

    // Real resolved secret is captured for detection (value kept in-model,
    // redacted only at the Finding boundary).
    const secret = db!.environment.find((e) => e.key === "POSTGRES_PASSWORD");
    expect(secret?.value).toBe(REAL_SECRET);
    expect(secret?.isReference).toBe(false);
  });

  it("maps privileged, host network, and the docker socket mount", () => {
    const [priv] = containersToServices(loadContainers("privileged-host"), "privileged-host.json");
    expect(priv!.privileged).toBe(true);
    expect(priv!.networkMode).toBe("host");
    expect(priv!.volumes.some((v) => v.source === "/var/run/docker.sock")).toBe(true);
  });

  it("keeps a loopback binding private (127.0.0.1 is not public)", () => {
    const [web] = containersToServices(loadContainers("clean-loopback"), "clean-loopback.json");
    const p = web!.ports.find((port) => port.containerPort === "80");
    expect(p!.hostIp).toBe("127.0.0.1");
    expect(web!.user).toBe("101:101");
    expect(web!.hasHealthcheck).toBe(true);
    expect(web!.restart).toBe("unless-stopped");
  });
});

describe("verdict over inspected containers", () => {
  it("(a) exposed DB port + real env secret → DON'T EXPOSE YET, blocker + loopback fix + redacted secret", () => {
    const report = scanContainers(loadContainers("exposed-db"), "exposed-db.json", STAMP);
    const a = assessExposure(report);

    expect(a.verdict).toBe("dont-expose");
    expect(ruleIds(report)).toContain("database-port-exposed");
    expect(ruleIds(report)).toContain("plaintext-secret");

    // db-port + secret group into ONE blocker for the service.
    expect(a.blockers).toHaveLength(1);
    const b = a.blockers[0]!;
    expect(b.headline).toContain("database port 5432");
    expect(b.headline).toContain("POSTGRES_PASSWORD");
    const fixes = [b.fix, ...(b.fixes ?? [])].filter(Boolean).join(" | ");
    expect(fixes).toContain("127.0.0.1:5432:5432");

    // The plaintext-secret finding is high and never leaks the raw value.
    const secretFinding = report.findings.find((f) => f.ruleId === "plaintext-secret");
    expect(secretFinding?.severity).toBe("high");
    const out = renderExpose(a, { color: false });
    expect(JSON.stringify(report)).not.toContain(REAL_SECRET);
    expect(out).not.toContain(REAL_SECRET);
  });

  it("(b) privileged + host network + docker socket → grouped 'root on the host' blocker", () => {
    const report = scanContainers(loadContainers("privileged-host"), "privileged-host.json", STAMP);
    const a = assessExposure(report);

    expect(a.verdict).toBe("dont-expose");
    const ids = ruleIds(report);
    expect(ids).toContain("privileged");
    expect(ids).toContain("host-network");
    expect(ids).toContain("docker-socket");

    // The three host-control facts collapse into a single blocker item.
    expect(a.blockers).toHaveLength(1);
    expect(a.blockers[0]!.headline).toMatch(/effectively has root on the host/i);
    expect(a.blockers[0]!.fixes?.length).toBe(3);
  });

  it("(c) clean loopback-only container, no secrets → LOOKS OK, no entry points", () => {
    const report = scanContainers(loadContainers("clean-loopback"), "clean-loopback.json", STAMP);
    const a = assessExposure(report);

    expect(a.verdict).toBe("looks-ok");
    expect(a.blockers).toHaveLength(0);
    expect(a.entryPoints).toHaveLength(0); // 127.0.0.1 is not internet-reachable
    expect(report.summary.counts.high).toBe(0);
  });
});

describe("auto-detection via scan(path)", () => {
  it("scans a docker-inspect JSON file the same as scanContainers, no flag needed", () => {
    const viaPath = scan(fixturePath("exposed-db"), STAMP);
    // A container-derived service is present (proves it wasn't parsed as Compose).
    expect(viaPath.services.some((s) => s.name === "sdtest-db")).toBe(true);
    expect(viaPath.findings.some((f) => f.ruleId === "database-port-exposed")).toBe(true);
  });

  it("builds a container context with no env files or tunnels", () => {
    const ctx = buildContextFromContainers(loadContainers("clean-loopback"), "x");
    expect(ctx.envFiles).toHaveLength(0);
    expect(ctx.tunnels).toHaveLength(0);
    expect(ctx.services).toHaveLength(1);
  });
});
