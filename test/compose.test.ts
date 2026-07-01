import { describe, it, expect } from "vitest";
import { parseComposeServices, parseEnvFile, parsePort } from "../src/core/compose";
import type { LoadedFile } from "../src/core/model";

const compose = (content: string): LoadedFile => ({
  path: "docker-compose.yml",
  kind: "compose",
  content,
});

describe("parsePort", () => {
  it("parses host:container short form", () => {
    const p = parsePort("8080:80");
    expect(p).toMatchObject({ hostPort: "8080", containerPort: "80", protocol: "tcp", published: true });
    expect(p?.hostIp).toBeUndefined();
  });

  it("parses ip:host:container and keeps the host interface", () => {
    expect(parsePort("127.0.0.1:5432:5432")).toMatchObject({
      hostIp: "127.0.0.1",
      hostPort: "5432",
      containerPort: "5432",
    });
  });

  it("parses a bare container port as published", () => {
    expect(parsePort("80")).toMatchObject({ containerPort: "80", published: true });
    expect(parsePort(3000)).toMatchObject({ containerPort: "3000", published: true });
  });

  it("parses the /udp protocol suffix", () => {
    expect(parsePort("53:53/udp")).toMatchObject({ containerPort: "53", protocol: "udp" });
  });

  it("parses bracketed IPv6 host", () => {
    expect(parsePort("[::]:8080:80")).toMatchObject({ hostIp: "::", hostPort: "8080", containerPort: "80" });
  });

  it("parses long object form", () => {
    expect(parsePort({ target: 80, published: 8080, host_ip: "127.0.0.1", protocol: "tcp" })).toMatchObject({
      containerPort: "80",
      hostPort: "8080",
      hostIp: "127.0.0.1",
      published: true,
    });
  });
});

describe("parseComposeServices", () => {
  it("returns [] for malformed or empty input (never throws)", () => {
    expect(parseComposeServices(compose(":\n  bad: [") )).toEqual([]);
    expect(parseComposeServices(compose("just a string"))).toEqual([]);
  });

  it("normalizes environment in both list and map form", () => {
    const [svc] = parseComposeServices(
      compose(`services:\n  a:\n    image: x\n    environment:\n      - FOO=bar\n      - REF=\${HOST_VAR}\n      - BARE\n`),
    );
    const env = Object.fromEntries(svc!.environment.map((e) => [e.key, e]));
    expect(env.FOO).toMatchObject({ value: "bar", isReference: false });
    expect(env.REF!.isReference).toBe(true);
    expect(env.BARE).toMatchObject({ value: "", isReference: false });
  });

  it("detects privileged, network_mode, restart, user, labels", () => {
    const [svc] = parseComposeServices(
      compose(
        `services:\n  a:\n    image: x\n    privileged: true\n    network_mode: host\n    restart: unless-stopped\n    user: "0:0"\n    labels:\n      com.example: yes\n`,
      ),
    );
    expect(svc).toMatchObject({
      privileged: true,
      networkMode: "host",
      restart: "unless-stopped",
      user: "0:0",
    });
    expect(svc!.labels["com.example"]).toBe("yes");
  });

  it("parses read-only volume mounts and the docker socket", () => {
    const [svc] = parseComposeServices(
      compose(`services:\n  a:\n    image: x\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock:ro\n`),
    );
    expect(svc!.volumes[0]).toMatchObject({ source: "/var/run/docker.sock", readOnly: true });
  });

  it("detects healthcheck presence and disablement", () => {
    const [withHc] = parseComposeServices(
      compose(`services:\n  a:\n    image: x\n    healthcheck:\n      test: ["CMD","true"]\n`),
    );
    expect(withHc!.hasHealthcheck).toBe(true);
    const [disabled] = parseComposeServices(
      compose(`services:\n  a:\n    image: x\n    healthcheck:\n      test: ["NONE"]\n`),
    );
    expect(disabled!.healthcheckDisabled).toBe(true);
  });

  it("detects resource limits (deploy and legacy)", () => {
    const [svc] = parseComposeServices(
      compose(`services:\n  a:\n    image: x\n    deploy:\n      resources:\n        limits:\n          memory: 128M\n`),
    );
    expect(svc!.hasResourceLimits).toBe(true);
  });
});

describe("parseEnvFile", () => {
  it("parses KEY=value lines, ignores comments, strips quotes and export", () => {
    const env = parseEnvFile({
      path: ".env",
      kind: "env",
      content: `# comment\nexport FOO="bar"\nEMPTY=\nREF=\${X}\n`,
    });
    const map = Object.fromEntries(env.entries.map((e) => [e.key, e]));
    expect(map.FOO).toMatchObject({ value: "bar", isReference: false });
    expect(map.EMPTY!.value).toBe("");
    expect(map.REF!.isReference).toBe(true);
  });
});
