import { parseComposeServices } from "../src/core/compose";
import type { LoadedFile, ScanContext } from "../src/core/model";

/** Build a ScanContext from an inline compose YAML string (no filesystem). */
export function ctxFromCompose(yaml: string, file = "test-compose.yml"): ScanContext {
  const loaded: LoadedFile = { path: file, kind: "compose", content: yaml };
  const services = parseComposeServices(loaded);
  return { target: "test", files: [file], services, envFiles: [], tunnels: [] };
}

/** Convenience: run a single rule against inline compose and return findings. */
export function runRuleOn(
  rule: { run: (ctx: ScanContext) => unknown },
  yaml: string,
) {
  return rule.run(ctxFromCompose(yaml)) as ReturnType<
    (typeof rule)["run"]
  > extends Array<infer T>
    ? T[]
    : never;
}

/**
 * Fake secret placeholder values planted in the example fixtures (compose +
 * .env.example). Redaction tests assert none of these ever appear in output.
 */
export const FIXTURE_SECRETS = [
  "CHANGE_ME_NOT_A_REAL_SECRET",
  "EXAMPLE_ONLY_DO_NOT_USE",
  "EXAMPLE_ONLY_ADMIN_TOKEN_DO_NOT_USE",
  "FAKE_TUNNEL_TOKEN_FOR_TESTS_ONLY",
];
