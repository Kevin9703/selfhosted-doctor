import type { Report } from "../core/model";
import { renderTerminal } from "./terminal";
import { renderJson } from "./json";
import { renderMarkdown } from "./markdown";

export type ReportFormat = "terminal" | "json" | "markdown";

export function renderReport(
  report: Report,
  format: ReportFormat,
  opts?: { color?: boolean; pretty?: boolean },
): string {
  switch (format) {
    case "json":
      return renderJson(report, { pretty: opts?.pretty });
    case "markdown":
      return renderMarkdown(report);
    case "terminal":
      return renderTerminal(report, { color: opts?.color });
    default: {
      const exhaustive: never = format;
      throw new Error(`Unknown report format: ${String(exhaustive)}`);
    }
  }
}
