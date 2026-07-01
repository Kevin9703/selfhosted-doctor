/**
 * Capped-bucket risk scoring.
 *
 * The score is computed from ACTIVE findings only (conditional/template
 * findings are shown but never lower the default score). Each finding adds a
 * weight to one risk bucket; each bucket is capped. This keeps the score
 * meaningful: one exposed database hurts a lot, but ten unpinned images barely
 * move it — and a large upstream Compose file no longer collapses to 0/100.
 */
import type { Finding, ScoreBucket } from "./model";

type Bucket =
  | "publicDataServiceExposure"
  | "privilegedOrHostControl"
  | "activePlaintextSecrets"
  | "sensitiveAppWithoutAccess"
  | "publicAppExposure"
  | "reliabilityHygiene"
  | "imagePinning";

/** Bucket caps, evaluated in this order. */
const BUCKET_CAP: Record<Bucket, number> = {
  publicDataServiceExposure: 40,
  privilegedOrHostControl: 30,
  activePlaintextSecrets: 25,
  sensitiveAppWithoutAccess: 25,
  publicAppExposure: 20,
  reliabilityHygiene: 10,
  imagePinning: 5,
};

const BUCKET_ORDER: Bucket[] = [
  "publicDataServiceExposure",
  "privilegedOrHostControl",
  "activePlaintextSecrets",
  "sensitiveAppWithoutAccess",
  "publicAppExposure",
  "reliabilityHygiene",
  "imagePinning",
];

/**
 * Map each rule to a bucket + per-finding weight. Rules absent from this map
 * (service-notes, rule-error) do not affect the score — they are context, not
 * penalties, and the underlying primary rule already scores the real risk.
 */
const RULE_BUCKET: Record<string, { bucket: Bucket; weight: number }> = {
  "database-port-exposed": { bucket: "publicDataServiceExposure", weight: 40 },
  privileged: { bucket: "privilegedOrHostControl", weight: 20 },
  "host-network": { bucket: "privilegedOrHostControl", weight: 20 },
  "docker-socket": { bucket: "privilegedOrHostControl", weight: 20 },
  "plaintext-secret": { bucket: "activePlaintextSecrets", weight: 15 },
  "default-secret-fallback": { bucket: "activePlaintextSecrets", weight: 15 },
  "cloudflared-tunnel-to-risky": { bucket: "sensitiveAppWithoutAccess", weight: 25 },
  "exposed-port": { bucket: "publicAppExposure", weight: 15 },
  "missing-healthcheck": { bucket: "reliabilityHygiene", weight: 3 },
  "missing-restart": { bucket: "reliabilityHygiene", weight: 3 },
  "runs-as-root": { bucket: "reliabilityHygiene", weight: 3 },
  "cloudflared-no-access": { bucket: "reliabilityHygiene", weight: 3 },
  "no-user": { bucket: "reliabilityHygiene", weight: 2 },
  "missing-resource-limits": { bucket: "reliabilityHygiene", weight: 2 },
  "missing-labels": { bucket: "reliabilityHygiene", weight: 1 },
  "latest-tag": { bucket: "imagePinning", weight: 2 },
  "unpinned-image": { bucket: "imagePinning", weight: 2 },
};

export interface ScoreResult {
  score: number;
  breakdown: ScoreBucket[];
}

/** Compute the 0–100 risk score and per-bucket breakdown from all findings. */
export function scoreActiveFindings(findings: Finding[]): ScoreResult {
  const sums = new Map<Bucket, number>();
  for (const finding of findings) {
    if ((finding.classification ?? "active") !== "active") continue;
    const mapping = RULE_BUCKET[finding.ruleId];
    if (!mapping) continue;
    sums.set(mapping.bucket, (sums.get(mapping.bucket) ?? 0) + mapping.weight);
  }

  let penalty = 0;
  const breakdown: ScoreBucket[] = [];
  for (const bucket of BUCKET_ORDER) {
    const raw = sums.get(bucket) ?? 0;
    if (raw === 0) continue;
    const capped = Math.min(raw, BUCKET_CAP[bucket]);
    breakdown.push({ bucket, penalty: capped, cap: BUCKET_CAP[bucket] });
    penalty += capped;
  }

  return { score: Math.max(0, Math.min(100, 100 - penalty)), breakdown };
}
