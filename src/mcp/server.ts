/**
 * Read-only MCP server for selfhosted-doctor.
 *
 * Exposes the deterministic scanner over the Model Context Protocol so agents
 * (Claude Code, Cursor, etc.) can inspect a local Compose setup. Every tool is
 * read-only: it reads files from a local path and returns a report. Nothing is
 * written, no daemon is touched, and secret values are redacted by the scanner
 * before they ever reach a tool result.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { scan } from "../core/scanner";
import { renderMarkdown } from "../report/markdown";
import type { Severity } from "../core/model";

const PATH_PROPERTY = {
  type: "string",
  description: "Path to a Docker Compose file or a directory containing Compose files.",
} as const;

const TOOLS: Tool[] = [
  {
    name: "scan_compose",
    description:
      "Scan a Docker Compose file or directory and return the full deterministic security report as JSON (risk score, findings, exposure map, service summaries). Secrets are redacted.",
    inputSchema: {
      type: "object",
      properties: { path: PATH_PROPERTY },
      required: ["path"],
    },
  },
  {
    name: "list_findings",
    description:
      "Scan a path and return only the list of security findings, optionally filtered by severity (high | medium | low | info).",
    inputSchema: {
      type: "object",
      properties: {
        path: PATH_PROPERTY,
        severity: {
          type: "string",
          enum: ["high", "medium", "low", "info"],
          description: "Optional severity filter.",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "list_exposed_services",
    description:
      "Scan a path and return the exposure map: which services publish which host ports to which interface.",
    inputSchema: {
      type: "object",
      properties: { path: PATH_PROPERTY },
      required: ["path"],
    },
  },
  {
    name: "generate_markdown_report",
    description: "Scan a path and return a human-readable Markdown security report.",
    inputSchema: {
      type: "object",
      properties: { path: PATH_PROPERTY },
      required: ["path"],
    },
  },
];

function textResult(text: string): CallToolResult {
  return { content: [{ type: "text", text }] };
}

function errorResult(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

function requirePath(args: Record<string, unknown> | undefined): string {
  const path = args?.["path"];
  if (typeof path !== "string" || path.trim() === "") {
    throw new Error("Missing required string argument: path");
  }
  return path;
}

function handleToolCall(name: string, args: Record<string, unknown> | undefined): CallToolResult {
  switch (name) {
    case "scan_compose": {
      const report = scan(requirePath(args));
      return textResult(JSON.stringify(report, null, 2));
    }
    case "list_findings": {
      const report = scan(requirePath(args));
      const severity = args?.["severity"];
      const findings =
        typeof severity === "string"
          ? report.findings.filter((f) => f.severity === (severity as Severity))
          : report.findings;
      return textResult(JSON.stringify(findings, null, 2));
    }
    case "list_exposed_services": {
      const report = scan(requirePath(args));
      return textResult(JSON.stringify(report.exposure, null, 2));
    }
    case "generate_markdown_report": {
      const report = scan(requirePath(args));
      return textResult(renderMarkdown(report));
    }
    default:
      return errorResult(`Unknown tool: ${name}`);
  }
}

/** Build the MCP Server instance (exposed for testing). */
export function createMcpServer(): Server {
  const server = new Server(
    { name: "selfhosted-doctor", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      return handleToolCall(name, args as Record<string, unknown> | undefined);
    } catch (err) {
      return errorResult(err instanceof Error ? err.message : String(err));
    }
  });

  return server;
}

/** Start the MCP server over stdio. Used by the `mcp` CLI command. */
export async function runMcpServer(): Promise<void> {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stderr is safe for logs; stdout is the MCP transport channel.
  process.stderr.write("selfhosted-doctor MCP server running on stdio\n");
}
