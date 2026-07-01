# Product Brief

## One-Liner

`selfhosted-doctor` is an AI-ready security doctor for self-hosted homelabs, starting with Docker Compose.

Core promise:

> Before exposing your NAS to the internet, run one command.

## Target Users

Primary users:

- People running services on a NAS, VPS, or home server
- Docker Compose self-hosters
- Cloudflare Tunnel / reverse proxy users
- Claude Code / Codex / Cursor users who want AI-readable reports
- Developers who care about security but are not full-time security engineers

Not the initial target:

- Enterprise Kubernetes teams
- Terraform-heavy cloud security teams
- Professional pentesters
- Users looking for a full homelab dashboard

## Problem

Self-hosted users can often make a service work, but they may not know whether it is safe to expose:

- Which services are reachable from the public internet?
- Which ports bind to `0.0.0.0`?
- Is Vaultwarden exposed without extra protection?
- Are Postgres, Redis, or MongoDB mapped to host ports?
- Are secrets written directly in Compose files?
- Is Cloudflare Tunnel configured without an Access policy?
- Are important data volumes backed up?

## Differentiation

Do not compete directly with:

- Trivy: general vulnerability and IaC scanning
- Checkov: enterprise IaC security
- Dockge: Docker Compose management
- Homepage / Dashy: dashboards
- CasaOS: personal cloud operating system

The gap:

> A homelab-focused safety report that translates Docker Compose and Cloudflare Tunnel exposure risks into advice self-hosted users can understand and act on.

## First-Version Value

Run:

```bash
selfhosted-doctor scan docker-compose.yml
```

Get:

- High / Medium / Low findings
- Exposure summary
- Service-specific notes
- Markdown and JSON reports
- Optional AI explanation
- Optional read-only MCP server

## Success Metrics

MVP success:

- 10 real Compose examples produce useful findings
- README explains the value in 30 seconds
- Users open issues asking for service support
- 100 stars in the first week after launch

30-day target:

- 500 stars
- Listed in at least one homelab / self-hosted awesome list
- 5 external rule contributions
