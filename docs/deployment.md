# Deploying Raiwall

This runbook covers the two supported deployment targets: Docker Compose and
Kubernetes (Helm). The production model is **Raiwall terminates public HTTPS**
and the dashboard/API live under `/.raiwall/` on the same listener.

> **Security posture:** `security.production_mode` refuses to boot with weak
> admin passwords, short or missing HMAC/PoW secrets, insecure session cookies,
> a non-HTTPS public URL, or HTTPS without a certificate source. Keep it enabled
> in production.

---

## 1. Prerequisites

- A DNS name for the dashboard, for example `raiwall.example.com`, pointing at
  the host (or load balancer).
- Ports **80/tcp** (ACME HTTP-01 + redirect) and **443/tcp+udp** (HTTPS, HTTP/3)
  reachable.
- For Compose: Docker Engine + Compose v2. For Helm: Kubernetes 1.27+ and Helm 3.
- A database: the bundled PostgreSQL for Compose, or an external PostgreSQL for
  Helm (required by the chart).
- Secrets generated locally:

```bash
openssl rand -hex 32   # RAIWALL_HMAC_SECRET (keys session token hashes)
openssl rand -hex 32   # RAIWALL_POW_SECRET
openssl rand -hex 24   # POSTGRES_PASSWORD
```

---

## 2. Docker Compose (public HTTPS)

The development stack (`docker-compose.yml`) is for local demos. Production uses
`docker-compose.prod.yml` and `config/raiwall.production.yaml`.

```bash
cp .env.example .env
# edit .env and set:
#   POSTGRES_PASSWORD
#   RAIWALL_HMAC_SECRET
#   RAIWALL_POW_SECRET
#   RAIWALL_PUBLIC_URL=https://raiwall.example.com
#   RAIWALL_ACME_EMAIL=ops@example.com
#   RAIWALL_ADMIN_PASSWORD   (optional; empty generates one)

docker compose -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.prod.yml logs -f raiwall
```

The container runs as uid 1000 and listens on **8080/8443**; Compose maps host
**80/443** to those ports. Do not change the container ports to 80/443.

First login:

- If you set `RAIWALL_ADMIN_PASSWORD`, use that.
- Otherwise the generated password is printed **once** at WARN level in the
  container logs: `docker compose -f docker-compose.prod.yml logs raiwall | grep
  auto-provisioned`.
- Open `https://raiwall.example.com/.raiwall/`.

Certificates: `server.auto_https: true` with the ACME email obtains certificates
for the configured site hostnames and the console host. To use your own
certificate instead, set `auto_https: false` and declare it under `certificates`
with `ssl_mode: manual`; production validation requires a certificate source.

### Console exposure

The dashboard/API share the public listener. Restrict it when possible:

```yaml
control:
  public_url: "https://raiwall.example.com"
  allowed_networks: ["203.0.113.0/24", "10.0.0.0/8"]
```

`allowed_networks` is enforced on the socket peer for `/.raiwall/*`, metrics, and
telemetry. An empty list allows every source (compatibility default). Health
probes (`/.raiwall/healthz`, `/.raiwall/readyz`) always bypass the allowlist.
Unknown hosts no longer redirect to the console.

---

## 3. Kubernetes (Helm)

The chart is fail-closed: rendering fails unless `database.password` (or
`database.existingSecret`), `config.control.public_url`, and
`config.server.acme.email` are set.

```bash
helm upgrade --install raiwall deploy/helm/raiwall \
  --namespace raiwall --create-namespace \
  --set database.host=postgres.example.com \
  --set database.user=raiwall \
  --set database.password='<strong-password>' \
  --set database.sslmode=require \
  --set config.control.public_url=https://raiwall.example.com \
  --set config.server.acme.email=ops@example.com \
  --set secrets.adminPassword='<one-time-admin-password>'
```

Notes:

- The Service exposes **80/443** and maps them to the container's 8080/8443
  (`service.httpPort` / `service.httpsPort`). Use `type: LoadBalancer` or an
  ingress controller that forwards TCP 80/443 to the Service; do not enable an
  ingress that terminates TLS unless you also set `auto_https: false`.
- `secrets.hmacSecret`/`powSecret` empty are generated once and preserved across
  upgrades. `secrets.adminPassword` empty means the app generates one and logs
  it once.
- Persistence: `/var/lib/raiwall` holds certificates and, for SQLite, the
  database. With external PostgreSQL, only certificates live on the PVC.
- Probes: `/.raiwall/healthz` (liveness/startup) and `/.raiwall/readyz`
  (readiness; database, active snapshot, and cluster sync).

---

## 4. Operator accounts

Create additional admins/viewers with the CLI until the Settings → Users page
lands (next milestone):

```bash
docker compose -f docker-compose.prod.yml exec raiwall \
  raiwall admin create-user --username alice --password '<strong-password>' --role admin
```

There is no default operator account and no `admin/admin`. Roles are enforced on
every control-plane request; role changes and deactivation take effect on the
next request (sessions are revalidated against the database).

---

## 5. Sessions and CSRF

- Opaque server-side sessions (only the HMAC of the token is stored), 8h idle /
  24h absolute by default; configurable under `control.session`.
- Secure `__Host-raiwall_session` cookie (HttpOnly, SameSite=Lax) when
  `control.session.secure: true`.
- Logout, password reset, role change, and deactivation revoke sessions
  immediately.
- Cookie-authenticated mutations require a same-origin `Origin`/`Referer`
  (cross-site requests receive 403). API keys are exempt.
- Login is throttled per IP and username (5 failures → 15 minute lockout).

---

## 6. Health and monitoring

| Endpoint | Purpose |
|---|---|
| `/.raiwall/healthz` | Process liveness only |
| `/.raiwall/readyz` | Database ping, active snapshot, cluster sync/Redis when configured |
| `/.raiwall/api/v1/status` | Authenticated status with the same component checks |
| `/.raiwall/metrics` | Authenticated Prometheus metrics |

Probes are wired in Compose and Helm. Alert channels are configured under
`telemetry.alert_channels`; they require authentication only if the webhook does.

---

## 7. Backups and retention

Use `pg_dump -Fc` against the control database and restore with `pg_restore
--clean --if-exists` while Raiwall is stopped. Backup scripts and a Helm
CronJob are part of the operations milestone; until then:

```bash
docker compose -f docker-compose.prod.yml exec -T postgres \
  pg_dump -U raiwall -Fc raiwall > raiwall-$(date +%F).dump
```

Forensic events honor `telemetry.retention` (default 30 days). Configuration
snapshots are retained for rollback; set `control.snapshot_retention` (planned)
to cap growth when `auto_apply` is on.

Test a restore into a scratch database before relying on a backup.

---

## 8. Security checklist before going live

- [ ] `security.production_mode: true` and boot validation passes.
- [ ] Strong admin password or generated password captured; no `admin/admin`.
- [ ] HMAC and PoW secrets generated and stored in a secret manager.
- [ ] HTTPS works (certificate issued), HTTP redirects to HTTPS.
- [ ] PostgreSQL is not published on the host; credentials are not defaults.
- [ ] `control.allowed_networks` restricts the console where possible.
- [ ] Session cookie is `Secure` + `__Host-`; CSRF rejects cross-origin writes.
- [ ] Login lockout verified.
- [ ] Probes return 200 and readiness goes 503 when the database is down.
- [ ] Backups configured and a restore has been rehearsed.
- [ ] Logs/alerts reviewed; telemetry retention matches policy.

---

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| `readyz` 503 | Database reachable? migrations finished? active snapshot present? |
| Certificate not issued | DNS points here, ports 80/443 open, ACME email set, no proxy stripping HTTP-01 |
| Login redirects to HTTPS loop | Public URL scheme/port and `server.auto_https` |
| Console 403 | `control.allowed_networks` does not include your IP |
| Mutations 403 with `cross-origin` | Browser Origin does not match `control.public_url` or the request Host |
| Sessions lost on restart | HMAC secret changed (must be stable) |
| `helm template` fails | Set the required values listed in the error (public URL, ACME email, DB password) |
