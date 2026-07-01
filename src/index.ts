/**
 * Library entry point for selfhosted-doctor.
 *
 * Programmatic users can `import { scan, renderReport } from "selfhosted-doctor"`.
 */
export { scan, buildContext, buildReport, type ScanOptions } from "./core/scanner";
export { runRules, RULES } from "./core/rules";
export { renderReport, type ReportFormat } from "./report";
export { renderTerminal } from "./report/terminal";
export { renderJson } from "./report/json";
export { renderMarkdown } from "./report/markdown";
export {
  detectServiceType,
  isDatabaseService,
  SERVICE_CATALOG,
  SERVICE_NOTES,
} from "./core/services";
export { explainReport, type ExplainOptions, type ExplainProvider } from "./ai/explain";

export type {
  Report,
  Finding,
  Severity,
  ScanContext,
  Rule,
  ComposeService,
  ExposureEntry,
  ServiceSummary,
  CloudflareTunnel,
} from "./core/model";
