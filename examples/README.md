# Example stacks

These are realistic homelab Docker Compose stacks used both as demo material and
as fixtures for the test suite. **They intentionally contain security issues** so
`selfhosted-doctor` has something to find — do not copy them as-is into
production.

Secrets here use obvious fake placeholders (e.g. `CHANGE_ME_NOT_A_REAL_SECRET`)
and each stack ships a committed `.env.example` template rather than a real
`.env`. That is the pattern to follow yourself: commit `.env.example`, and keep
your real `.env` out of version control (it's in `.gitignore`).

Run the scanner against any of these directories:

```sh
selfhosted-doctor scan examples/vaultwarden-cloudflare
```

## vaultwarden-cloudflare

Vaultwarden (a self-hosted password manager) fronted by a Cloudflare Tunnel.

Issues the scanner flags:

- Vaultwarden published directly to a public host port (`8080:80`) — a sensitive
  app that should never be exposed directly
- Plaintext `ADMIN_TOKEN` secret in both the compose file and `.env.example`
- `SIGNUPS_ALLOWED=true` leaving open registration on an exposed instance
- `:latest` image tags on both `vaultwarden` and `cloudflared`
- Missing healthcheck and missing restart policy on `vaultwarden`
- Cloudflare Tunnel routing to a sensitive service with no Cloudflare Access
  policy in front of it

## immich-postgres

Immich (self-hosted photo library) with its Postgres + Redis backends.

Issues the scanner flags:

- Immich server published on a public host port (`2283:2283`)
- Postgres database published to the host (`5432:5432`) — an exposed database
- Plaintext `DB_PASSWORD` / `POSTGRES_PASSWORD` secrets in the compose file and
  `.env.example`
- Missing healthchecks across the services

## nextcloud-db

Nextcloud with MariaDB, Redis, a Traefik reverse proxy, and Watchtower.

Issues the scanner flags:

- Nextcloud published on a public host port (`8081:80`)
- MariaDB database published to the host (`3306:3306`) — an exposed database
- Plaintext `MYSQL_ROOT_PASSWORD` / `MYSQL_PASSWORD` secrets
- Traefik and Watchtower mounting the Docker socket
  (`/var/run/docker.sock`) — root-equivalent access to the host
- Watchtower running `privileged: true` and with `network_mode: host`
- `:latest` image tags on `nextcloud` and `redis`
- Missing healthchecks across the services
- The proxy's `80`/`443` ingress ports are treated as expected reverse-proxy
  ingress (medium), not the same high-risk exposure as an app or database port
