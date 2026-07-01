import type { Finding, Rule } from "../model";
import { parseImageRef } from "./util";

export const rule: Rule = {
  id: "latest-tag",
  description: "Flags images using the `latest` tag (explicit or implicit).",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      const image = service.image;
      if (image === undefined || image === "") {
        continue;
      }
      const ref = parseImageRef(image);
      const isLatest = ref.tag === "latest" || ref.tag === undefined;
      if (isLatest && ref.digest === undefined) {
        findings.push({
          ruleId: rule.id,
          severity: "medium",
          title: `Uses the "latest" image tag`,
          service: service.name,
          file: service.file,
          detail:
            `Service "${service.name}" pulls "${image}", which resolves to the mutable "latest" tag. Deploys become non-reproducible and can silently change behavior.`,
          recommendation:
            "Pin a specific version tag (e.g. `image:1.2.3`) instead of relying on `latest`.",
          evidence: image,
        });
      }
    }
    return findings;
  },
};
