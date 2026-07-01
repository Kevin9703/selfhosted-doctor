import type { Finding, Rule } from "../model";
import { parseImageRef } from "./util";

export const rule: Rule = {
  id: "unpinned-image",
  description:
    "Flags images pinned to a specific tag but not to an immutable digest.",
  run(ctx) {
    const findings: Finding[] = [];
    for (const service of ctx.services) {
      const image = service.image;
      if (image === undefined || image === "") {
        continue;
      }
      const ref = parseImageRef(image);
      // Skip when latest-tag already fires (latest / implicit-latest).
      if (ref.tag === undefined || ref.tag === "latest") {
        continue;
      }
      // Specific tag present but no digest.
      if (ref.digest === undefined) {
        findings.push({
          ruleId: rule.id,
          severity: "low",
          title: `Image is not pinned by digest`,
          service: service.name,
          file: service.file,
          detail:
            `Service "${service.name}" pins the tag "${ref.tag}" but not a digest. Tags can be re-pushed, so the same tag may resolve to a different image over time.`,
          recommendation:
            "Pin the image by digest (e.g. `image:tag@sha256:...`) for immutable, reproducible deploys.",
          evidence: image,
        });
      }
    }
    return findings;
  },
};
