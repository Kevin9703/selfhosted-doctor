# Implementation Notes

Design decisions, tradeoffs, and known gaps for the v0.1 MVP.

## Architecture

```
src/
  cli.ts                 commander entry (scan / explain / mcp)
  index.ts               library exports
  core/
    model.ts             shared types (Report, Finding, ScanContext, Rule, …)
    loader.ts            discover + read compose / .env / cloudflared files
    compose.ts           normalize Compose (ports, volumes, env, healthcheck)
    services.ts          service catalog, detection, service-specific notes
    secrets.ts           secret key/value heuristics + redaction
    cloudflare.ts        static cloudflared tunnel config parsing
    scanner.ts           orchestrator → Report (risk score, exposure map)
    rules/               one file per rule; index.ts assembles + sorts
  report/ terminal.ts | json.ts | markdown.ts | index.ts
  ai/ explain.ts         mock provider (explains, never discovers)
  mcp/ server.ts         read-only MCP server over stdio
```

The pipeline is deterministic: `load → parse → run rules → assemble Report → render`. Everything downstream of the scanner (terminal/JSON/Markdown reporters, MCP, AI) consumes the same `Report` object, so there is exactly one source of truth.

**Rules are the only producers of `Finding`s.** They receive an immutable `ScanContext` and return findings. A rule that throws is caught and skipped (`runRules`) so one bad rule can't crash a scan.

## Key decisions & tradeoffs

- **TypeScript + tsup, distributed via npm.** Makes `npx selfhosted-doctor` the install-free entry point the product brief wants, and gives mature MCP SDK support.
- **No zod.** The MCP server uses the low-level `Server` API with hand-written JSON Schemas, and Compose input is validated defensively (tolerant parsing, never throws). This keeps the dependency surface small. If validation needs grow, zod is an easy add.
- **Redaction happens before a value reaches a `Finding`.** `redactValue` returns a constant `***redacted***`. Because no formatter ever sees a raw secret, terminal/JSON/Markdown/MCP/AI output are all safe by construction. Tests assert that known fixture secrets never appear in any output.
- **Image-first service detection.** Container names are frequently prefixed with the stack name (`nextcloud_db`), which pollutes name-based matching. Detection checks the image across the whole catalog first, then falls back to the service key / container name.
- **Severity tuning for signal over noise.** The spec lists several hygiene items as "medium"; a few that would fire on almost every service (`unpinned-image`, `no-user`, `missing-resource-limits`, `missing-labels`) were dialed to `low`/`info` so the High/Medium sections stay actionable. `no-user` only fires for services that actually publish a public port.
- **Reverse-proxy ingress is context-aware.** A proxy/tunnel publishing `80`/`443` is expected, so `exposed-port` downgrades those to `medium` instead of `high`.
- **Finding classification (v0.1.1).** Every finding is tagged **active**, **conditional**, or **template**. *Active* findings apply to the default/running stack. *Conditional* findings come from services gated behind a Compose `profiles:` key — they only run when you opt into that profile, so they're reported but excluded from the default score. *Template* findings come from example/placeholder sources (`.env.example`, `.env.sample`, `.env.template`, and files under `examples/`); these are downgraded to info (e.g. `Default secret in template env file`) rather than emitting a high-severity plaintext-secret finding. `--profile <name>` (repeatable) promotes the named profile(s) into scoring, and `--all-profiles` scores every service.
- **Capped-bucket scoring (v0.1.1).** The score is computed from **active findings only**, using capped risk buckets instead of pure per-finding subtraction:

  ```text
  score = 100 − Σ (capped active-bucket penalties)

  publicDataServiceExposure  capped at 40
  privilegedOrHostControl    capped at 30
  activePlaintextSecrets     capped at 25
  sensitiveAppWithoutAccess  capped at 25
  publicAppExposure          capped at 20
  reliabilityHygiene         capped at 10
  imagePinning               capped at  5
  ```

  Capping keeps the score meaningful: one exposed database hurts a lot, but ten unpinned images barely move it, and a big upstream Compose file no longer collapses to `0/100`. Conditional and template findings are shown but never lower the default score. The old linear `100 − (high·15 + medium·6 + low·2)` model is replaced. This is still a heuristic for glanceability, not a calibrated metric — and it grades your **active** configuration, not a universal security posture.

## Known gaps

- **No `${VAR}` interpolation.** `.env` values are scanned for secrets independently, but the scanner does not substitute them into Compose before evaluating rules. A bare `${X}` reference is treated as safe (not plaintext), which is correct. Fallback defaults (`${X:-secret}`) are the exception: as of v0.1.1 they're flagged, because the literal default ships when the variable is unset. Cross-file resolution of exposure/values is still not done.
- **`env_file:` directives are not followed** per service; only discovered `.env`-style files are scanned as secret sources.
- **Cloudflare Access detection is a heuristic** (`/access/i` over the config text). Access policies actually live in the Cloudflare Zero Trust dashboard, which a static file scan cannot see, so this errs toward flagging.
- **`runs-as-root` / `no-user` can't see image defaults.** We only know what the Compose file declares; an image that drops privileges internally may still be flagged.
- **No digest/tag vulnerability data.** `latest-tag` / `unpinned-image` are hygiene checks, not CVE lookups (that's Trivy's job).
- **Single-node Compose only.** No Swarm, Kubernetes, or Podman-specific semantics.

## What should come next

1. **More service rules** — Home Assistant, Gitea, Paperless, Portainer, and per-service exposure defaults.
2. **`.env` ⇄ Compose resolution** so exposure and secret findings can reason across files.
3. **Real AI providers** behind the existing `ExplainProvider` interface (Anthropic, OpenAI, Ollama, OpenAI-compatible) with the same "explain, don't invent" contract and pre-send redaction.
4. **Mermaid exposure map** in the Markdown report (planned for v0.2).
5. **Richer Cloudflare Tunnel parsing** — token-based tunnels declared in Compose, multiple configs, per-hostname Access hints.
6. **Config file** for per-project rule allow/deny and severity overrides.

## Testing

`vitest` covers the parser, secret heuristics + redaction, service detection (including the `nextcloud_db` regression), every rule group, the three reporters, the MCP server (via an in-memory client/server transport), and end-to-end scans of all three example stacks. Redaction is asserted across every output surface.
