import type { Report } from "../core/model";

export function renderJson(report: Report, opts?: { pretty?: boolean }): string {
  const pretty = opts?.pretty ?? true;
  return pretty ? JSON.stringify(report, null, 2) : JSON.stringify(report);
}
