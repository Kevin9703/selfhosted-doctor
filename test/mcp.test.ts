import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../src/mcp/server";
import { FIXTURE_SECRETS } from "./helpers";

let client: Client;

beforeAll(async () => {
  const server = createMcpServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(clientTransport);
});

afterAll(async () => {
  await client?.close();
});

function textOf(result: unknown): string {
  const content = (result as { content: Array<{ type: string; text?: string }> }).content;
  return content.map((c) => c.text ?? "").join("\n");
}

describe("MCP server", () => {
  it("advertises the four read-only tools", async () => {
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual([
      "generate_markdown_report",
      "list_exposed_services",
      "list_findings",
      "scan_compose",
    ]);
  });

  it("scan_compose returns a JSON report", async () => {
    const res = await client.callTool({
      name: "scan_compose",
      arguments: { path: "examples/immich-postgres" },
    });
    const report = JSON.parse(textOf(res));
    expect(report.tool).toBe("selfhosted-doctor");
    expect(Array.isArray(report.findings)).toBe(true);
  });

  it("list_findings filters by severity", async () => {
    const res = await client.callTool({
      name: "list_findings",
      arguments: { path: "examples/immich-postgres", severity: "high" },
    });
    const findings = JSON.parse(textOf(res));
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((f: { severity: string }) => f.severity === "high")).toBe(true);
  });

  it("generate_markdown_report returns markdown, list_exposed_services returns the map", async () => {
    const md = await client.callTool({
      name: "generate_markdown_report",
      arguments: { path: "examples/nextcloud-db" },
    });
    expect(textOf(md)).toContain("## Exposure Map");

    const exp = await client.callTool({
      name: "list_exposed_services",
      arguments: { path: "examples/nextcloud-db" },
    });
    expect(Array.isArray(JSON.parse(textOf(exp)))).toBe(true);
  });

  it("returns an error result for a missing path argument", async () => {
    const res = await client.callTool({ name: "scan_compose", arguments: {} });
    expect((res as { isError?: boolean }).isError).toBe(true);
  });

  it("never leaks a raw secret through any tool", async () => {
    const res = await client.callTool({
      name: "scan_compose",
      arguments: { path: "examples/nextcloud-db" },
    });
    const text = textOf(res);
    for (const secret of FIXTURE_SECRETS) {
      expect(text).not.toContain(secret);
    }
  });
});
