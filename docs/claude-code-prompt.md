# Claude Code Prompt

Use this prompt to start implementation work.

```text
We are building an open-source project named `selfhosted-doctor`.

Product positioning:
- AI-ready security checks for self-hosted homelabs, starting with Docker Compose.
- Target users are NAS / homelab / self-hosted users who deploy services with Docker Compose and may expose them through Cloudflare Tunnel or reverse proxies.
- The tool must be useful without AI. AI is an optional explanation layer.

Core promise:
"Before exposing your NAS to the internet, run one command."

MVP scope:
1. Build a TypeScript CLI package.
2. Command: `selfhosted-doctor scan [path]`
3. Parse Docker Compose YAML files.
4. Scan either one compose file or a directory containing compose files.
5. Detect high-value homelab security risks:
   - privileged containers
   - host network mode
   - ports exposed to 0.0.0.0 or unspecified host
   - exposed database ports
   - Docker socket mounts
   - plaintext secrets in compose or .env-like files
   - latest image tags
   - missing healthcheck
   - missing restart policy
   - containers running as root
6. Identify common services:
   - vaultwarden
   - bitwarden
   - nextcloud
   - immich
   - jellyfin
   - homeassistant
   - gitea
   - postgres
   - mysql
   - mariadb
   - redis
   - mongodb
   - traefik
   - nginx
   - caddy
   - cloudflared
7. Generate:
   - terminal summary
   - JSON report
   - Markdown report
8. Add optional command: `selfhosted-doctor explain report.json --provider mock`
   - For MVP, implement a provider interface and a mock provider.
   - Do not call real OpenAI/Anthropic APIs yet unless the interface is clean.
9. Add a read-only MCP server skeleton:
   - `selfhosted-doctor mcp`
   - tools:
     - scan_compose
     - list_findings
     - list_exposed_services
     - generate_markdown_report
   - The MCP server must not modify files.

Technical preferences:
- TypeScript
- Use `yaml` for YAML parsing
- Use `zod` for report schemas
- Use `commander` or `cac` for CLI
- Use `vitest` for tests
- Use `@modelcontextprotocol/sdk` for MCP if practical

Repository structure:
src/
  cli/
  scanner/
  rules/
  report/
  ai/
  mcp/
examples/
tests/

Important product constraints:
- Do not auto-fix files in MVP.
- Do not connect to Docker daemon.
- Do not call Cloudflare API.
- Do not leak secret values in reports.
- Do not make LLM output the source of truth for security findings.
- Deterministic scanner first, AI explanation second.

Deliverables:
1. Working CLI with `scan`
2. Markdown and JSON report output
3. At least 3 example compose projects:
   - vaultwarden-cloudflare
   - immich-public
   - nextcloud-basic
4. Unit tests for core rules
5. README with:
   - one-line positioning
   - quickstart
   - sample output
   - AI/MCP section
   - disclaimer

Please first inspect the repo, propose a minimal implementation plan, then implement the MVP. Keep the code simple and testable.
```
