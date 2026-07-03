/**
 * Library entry point for selfhosted-doctor.
 *
 * Programmatic users can `import { scan, renderReport } from "selfhosted-doctor"`.
 */
export {
  scan,
  scanContainers,
  buildContext,
  buildContextFromContainers,
  buildReport,
  type ScanOptions,
} from "./core/scanner";
export {
  containersToServices,
  containerToService,
  looksLikeDockerInspect,
  parseDockerInspectText,
  maybeLoadDockerInspectFile,
  type DockerInspectContainer,
} from "./core/docker-inspect";
export { collectRunningContainers, RUNNING_TARGET } from "./core/docker-cli";
export { runRules, RULES } from "./core/rules";
export { classifyFindings, isEnvTemplateFile, isServiceActive } from "./core/classify";
export { scoreActiveFindings } from "./core/score";
export { renderReport, type ReportFormat } from "./report";
export { renderTerminal } from "./report/terminal";
export { renderExpose } from "./report/expose";
export {
  assessExposure,
  decideVerdict,
  labelFromPath,
  type Verdict,
  type ExposeAssessment,
  type ExposeItem,
  type EntryPoint,
} from "./core/verdict";
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
  Classification,
  SeverityCounts,
  ScoreBucket,
  ScanContext,
  Rule,
  ComposeService,
  ExposureEntry,
  ServiceSummary,
  CloudflareTunnel,
} from "./core/model";
