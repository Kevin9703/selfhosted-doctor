# MVP Spec

## Goal

Prove that self-hosted users want a local-first safety check before exposing Docker Compose services to the internet.

## CLI

Planned commands:

```bash
selfhosted-doctor scan [path]
selfhosted-doctor scan [path] --format markdown
selfhosted-doctor scan [path] --output selfhosted-report.md
selfhosted-doctor explain report.json --provider mock
selfhosted-doctor mcp
```

`path` can be:

- `docker-compose.yml`
- `compose.yml`
- A directory containing Compose files

## Report Formats

Must support:

- Terminal summary
- JSON
- Markdown

Markdown report sections:

- Summary
- High Risk
- Medium Risk
- Low Risk
- Exposure Map
- Service Notes
- Suggested Fixes
- Disclaimer

## Docker Compose Rules

High:

- `privileged: true`
- `network_mode: host`
- Port mappings bound to `0.0.0.0` or unspecified host
- Plaintext secrets in Compose or `.env`-style files
- Docker socket mount: `/var/run/docker.sock`
- Database ports exposed to the host

Medium:

- Missing `restart` policy
- Missing `healthcheck`
- `latest` image tag
- Image not pinned by digest
- Container runs as root

Low:

- Missing resource limits
- Missing labels / metadata

## Service Detection

Detect by service name, image name, container name, and labels.

Initial service list:

- `vaultwarden`
- `bitwarden`
- `nextcloud`
- `immich`
- `jellyfin`
- `homeassistant`
- `gitea`
- `postgres`
- `mysql`
- `mariadb`
- `redis`
- `mongodb`
- `traefik`
- `nginx`
- `caddy`
- `cloudflared`

## Service-Level Notes

Vaultwarden:

- Direct public exposure is High.
- Recommend Cloudflare Access, VPN, or strong reverse-proxy authentication.

Immich:

- Exposed database is High.
- Remind users to back up photo library and database volumes.

Nextcloud:

- Exposed database is High.
- Warn when proxy / trusted domain hints are missing.

Jellyfin:

- Public exposure is Medium by default.
- Remind users to secure admin access and use strong credentials.

Databases:

- Host port mapping is High unless explicitly documented as local-only.

Cloudflared:

- Tunnel config without Access hint is Medium.
- Tunnel to high-risk services may become High.

## Secret Detection

Use heuristic matching for keys like:

- `PASSWORD`
- `PASS`
- `TOKEN`
- `SECRET`
- `API_KEY`
- `PRIVATE_KEY`
- `SMTP_PASS`
- `DATABASE_URL`

Never print full secret values. Redact before terminal, JSON, Markdown, MCP, or AI output.

## Cloudflare Tunnel MVP

Static scan only.

Look for:

- `cloudflared/config.yml`
- `config.yml`
- Compose volume mounts pointing to tunnel config
- `ingress.hostname`
- `ingress.service`
- Access policy hints

Do not:

- Call Cloudflare API
- Query DNS
- Probe public internet reachability

## AI Explain

AI explanation must not discover findings. It only explains deterministic scanner output.

MVP provider:

- `mock`

Later providers:

- OpenAI
- Anthropic
- Ollama
- OpenAI-compatible endpoints

## MCP Server

Read-only MVP tools:

- `scan_compose`
- `list_findings`
- `list_exposed_services`
- `generate_markdown_report`

No write tools in v0.1.

## Suggested Tech Stack

- TypeScript
- `yaml`
- `zod`
- `commander` or `cac`
- `picocolors`
- `fast-glob`
- `vitest`
- `@modelcontextprotocol/sdk`

## Acceptance Criteria

- Scan one Compose file
- Scan a directory of Compose files
- Output terminal, JSON, and Markdown reports
- Detect at least 15 risk rules
- Detect at least 10 common services
- Redact secret values
- Include a read-only MCP server skeleton
- Include unit tests for core rules
- Include 3 example stacks
