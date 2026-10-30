# Configuration reference

Raiwall is configured by one versioned YAML document, `raiwall.yaml`. The same
document drives the binary, Docker Compose, and the Helm chart; there is no
separate Caddyfile dialect.

- **Schema version:** `version: 1`
- **Deployable baseline:** [`config/raiwall.yaml`](../config/raiwall.yaml)
- **Annotated reference:** [`examples/raiwall.yaml`](../examples/raiwall.yaml)
- **Helm mirror:** [`deploy/helm/raiwall/values.yaml#config`](../deploy/helm/raiwall/values.yaml)

---

## 1. Discovery

When `--config` is omitted, the loader probes in this order and stops at the
first existing file:

```text
--config <path>
  → $RAIWALL_CONFIG
  → /etc/raiwall/raiwall.yaml
  → ./raiwall.yaml
  → config/raiwall.yaml
  → hard failure with an actionable error
```

Only `.yaml` / `.yml` files are accepted. A `.caddyfile` or a file named
`Caddyfile` is rejected at startup with a migration hint.

## 2. Precedence

```text
built-in defaults  <  YAML document  <  curated RAIWALL_* environment variables
```

The environment layer only carries deployment-specific values. Everything
declarative (applications, ACLs, policies, templates) stays in the file.

### Environment overrides

| Variable | Overrides | Notes |
| :--- | :--- | :--- |
| `RAIWALL_CONFIG` | config path | Discovery only |
| `RAIWALL_HTTP_LISTEN` | `server.http.listen` | Host:port |
| `RAIWALL_HTTPS_LISTEN` | `server.https.listen` | Host:port |
| `RAIWALL_HTTP_ENABLED` | `server.http.enabled` | Boolean |
| `RAIWALL_HTTPS_ENABLED` | `server.https.enabled` | Boolean |
| `RAIWALL_HTTP3` | `server.https.http3` | Boolean |
| `RAIWALL_TLS_MIN_VERSION` | `server.https.tls_min_version` | `1.2` / `1.3` |
| `RAIWALL_LOG_LEVEL` | `logging.level` | `debug`/`info`/`warn`/`error` |
| `RAIWALL_LOG_FORMAT` | `logging.format` | `json`/`console` |
| `RAIWALL_CADDY_ADMIN` | `caddy.admin.listen` | `off` or host:port |
| `RAIWALL_CERTMAGIC_ROOT` | `caddy.storage.root` | Certificate storage path |
| `RAIWALL_DATABASE_URL` | `storage.database_url` or both bound stores | Legacy `DATABASE_URL` is still honoured when no storage block exists |
| `RAIWALL_CONTROL_DSN` | DSN of the store bound to `storage.control` | Driver inferred from the DSN scheme |
| `RAIWALL_TELEMETRY_DSN` | DSN of the store bound to `storage.telemetry` | Driver inferred from the DSN scheme |
| `RAIWALL_ADMIN_USERNAME` | `control.bootstrap_admin.username` | |
| `RAIWALL_ADMIN_PASSWORD` | `control.bootstrap_admin.password` | Empty = generated once |
| `RAIWALL_HMAC_SECRET` | `control.hmac_secret` | Session cookie signing |
| `RAIWALL_POW_SECRET` | `bot.pow_secret` | Stateless PoW signing |
| `RAIWALL_SESSION_SECRET` | `auth.session_secret` | Only when `auth:` exists |
| `RAIWALL_SIDECAR_LISTEN` | `sidecar.listen` | Only when `sidecar:` exists |
| `RAIWALL_WAF_MODE` | `waf.mode` | `defense`/`audit`/`offline` |

`RAIWALL_CONTROL_DSN` and `RAIWALL_TELEMETRY_DSN` replace the DSN of the named
store only; they do not add new stores.

## 3. Secrets

The loader resolves placeholders inside scalar values:

| Form | Behaviour |
| :--- | :--- |
| `${VAR}` | Empty string when unset |
| `${VAR:-fallback}` | Fallback when unset or empty |
| `${VAR:?message}` | Fails with `message` when unset or empty |
| `RAIWALL_*_FILE` | Any lookup of `VAR` also checks `VAR_FILE` and reads its contents (Docker/Kubernetes secret mounts) |

Inline plaintext values for secret-bearing keys (`hmac_secret`, `password`,
`password_hash`, `pow_secret`, `session_secret`, `client_secret`, `key_pem`,
`dsn`, `database_url`, alert channel `url`) trigger a startup warning. Set
`security.strict_secrets: true` to turn that warning into a hard failure.

When `control.bootstrap_admin.password` is empty, Raiwall generates a random
password on first start and logs it once at WARN level.

---

## 4. Top-level sections

All durations are Go duration strings (`500ms`, `10s`, `2h`, `720h`).

### `server`

| Key | Default | Constraints |
| :--- | :--- | :--- |
| `http.enabled` | `true` | At least one listener must be enabled |
| `http.listen` | `":8080"` | Valid host:port |
| `https.enabled` | `true` | |
| `https.listen` | `":8443"` | Must differ from `http.listen` |
| `https.http3` | `false` | Enables HTTP/3 over QUIC |
| `https.tls_min_version` | `"1.2"` | `1.2` or `1.3` |
| `auto_https` | `false` | `true` lets Caddy obtain certificates for unknown SNI |
| `acme.email` | `""` | ACME account email |
| `acme.ca` | `""` | Custom ACME directory URL |
| `acme.staging` | `false` | Use the staging CA |

### `caddy`

| Key | Default | Constraints |
| :--- | :--- | :--- |
| `admin.listen` | `"off"` | `off` or host:port |
| `storage.module` | `file_system` | Only `file_system` is supported |
| `storage.root` | `/var/lib/raiwall/certmagic` | Writable path |

### `logging`

| Key | Default | Constraints |
| :--- | :--- | :--- |
| `level` | `info` | `debug`, `info`, `warn`, `error` |
| `format` | `json` | `json` or `console` |
| `output` | `stderr` | `stderr`, `stdout`, or a file path |

### `storage`

`database_url` is a shortcut that binds **both** the control and telemetry
roles to one database. It is mutually exclusive with `stores`.

| Key | Default | Notes |
| :--- | :--- | :--- |
| `database_url` | unset | `postgres://…`, `file:…`, or `memory` |
| `stores.<name>.driver` | inferred | `sqlite`, `postgres`, `clickhouse`, `memory` |
| `stores.<name>.dsn` | — | Required unless the driver is `memory` |
| `stores.<name>.max_open` | `0` (driver default) | Non-negative |
| `stores.<name>.max_idle` | `0` (driver default) | Non-negative |
| `stores.<name>.retention` | `720h` for telemetry | Forensic retention |
| `stores.<name>.prune_interval` | `1h` for telemetry | Retention sweep cadence |
| `control` | first store | Store name bound to the control role |
| `telemetry` | same as control | Store name bound to telemetry |

With no `database_url` and no `stores`, Raiwall ships two embedded SQLite
databases: `raiwall_control.db` and `raiwall_telemetry.db`, both under
`/var/lib/raiwall`.

### `control`

| Key | Default | Notes |
| :--- | :--- | :--- |
| `hmac_secret` | generated per boot | Set a stable 32+ byte value in production |
| `db_path` | unset | Legacy single-store override; prefer `storage` |
| `bootstrap_admin.username` | `admin` | Required |
| `bootstrap_admin.password` | generated | Logged once at WARN level |
| `bootstrap_admin.role` | `admin` | `admin` or `viewer` |

### `security`

| Key | Default | Notes |
| :--- | :--- | :--- |
| `strict_secrets` | `false` | Reject inline plaintext secrets instead of warning |

### `waf`

| Key | Default | Constraints |
| :--- | :--- | :--- |
| `mode` | `defense` | `defense`, `audit`, `offline` |
| `block_status_code` | `403` | 200–599 |
| `block_response_body` | `""` | Inline body; templates take precedence |
| `offline_status_code` | `503` | 200–599 |
| `offline_response_body` | `""` | |
| `strip_headers` | `[]` | Response headers removed before proxying |
| `ast_timeout` | `5ms` | **Hard ceiling 5ms** |
| `max_param_size` | `32768` | **Hard ceiling 32 KiB** |

### `bot`

| Key | Default | Constraints |
| :--- | :--- | :--- |
| `defense` | `defense` | `defense`, `challenge`, `strict`, `audit`, `off` |
| `pow_difficulty` | `50000` | Non-negative; 1,000–200,000 when PoW is enabled |
| `pow_secret` | generated per boot | Stable value for shared clearance cookies |
| `clearance_ttl` | `2h` | |
| `honeypot_trap` | `true` | Ban clients that hit trap URLs |

### `rate_limit` (optional)

| Key | Default | Notes |
| :--- | :--- | :--- |
| `tier1_rate` / `tier1_period` / `tier1_burst` | runtime defaults | Access velocity |
| `tier2_threshold` / `tier2_window` / `tier2_ban_duration` | runtime defaults | Attack frequency |
| `tier3_threshold` / `tier3_window` / `tier3_ban_duration` | runtime defaults | Scanner trap |
| `storage` | `memory` | `memory` or `redis` |
| `storage_addr` | `""` | Required when `storage: redis` |

### `waiting_room` (optional)

| Key | Default | Notes |
| :--- | :--- | :--- |
| `enabled` | `false` | |
| `max_concurrent` | runtime default | In-flight request ceiling |
| `max_queue_depth` | runtime default | Bounded admission queue |
| `admission_rate` | runtime default | Admitted requests per second |
| `token_ttl` | runtime default | Admission token lifetime |
| `target_paths` | `[]` | Empty = every path |

### `auth` (optional, portal-wide gate)

| Key | Notes |
| :--- | :--- |
| `provider` | `simple` (local users) or `oidc` |
| `issuer_url`, `client_id`, `client_secret`, `redirect_url`, `scopes` | OIDC settings |
| `users[]` | `username`, `password` (hashed at boot) or `password_hash`, `email`, `name`, `roles` |
| `session_secret` | Signs portal sessions |
| `session_cookie` | Default `rw_session` |
| `session_ttl` | Session lifetime |
| `session_secure` | Force the `Secure` cookie flag |
| `bypass_paths` | Unauthenticated path prefixes |

### `telemetry` (optional)

| Key | Default | Notes |
| :--- | :--- | :--- |
| `flush_interval` | runtime default | Ring-buffer batch flush |
| `buffer_size` | runtime default | Queued events before dropping |
| `retention` | `720h` | Forensic retention |
| `alert_channels[]` | `[]` | `name`, `url` (Shoutrrr), `events`, `cooldown` |

### `sidecar` (optional)

| Key | Default | Notes |
| :--- | :--- | :--- |
| `enabled` | `false` | Envoy `ext_proc/v3` gRPC service |
| `listen` | `":50051"` | Bound by exactly one listener |
| `max_body_size` | `1048576` | Bytes |

### `geoip` and `threat_feeds`

| Key | Notes |
| :--- | :--- |
| `geoip.country` | MaxMind `GeoLite2-Country.mmdb` path (country + continent) |
| `geoip.city` | MaxMind `GeoLite2-City.mmdb` path (adds city, latitude, longitude) |
| `geoip.asn` | MaxMind `GeoLite2-ASN.mmdb` path |
| `geoip.auto_update` | Download missing/stale editions on boot; requires `RAIWALL_GEOIP_LICENSE_KEY` |
| `threat_feeds.<name>` | Local file with one CIDR per line; exposed as `in_feed(client_ip, "<name>")` |

Geo enrichment only runs for public client IPs: loopback and RFC1918 addresses are
skipped. Behind a proxy set `proxy.client_ip_source: header` so the real client
address is inspected instead of the load balancer's.

To enable the Geo Location globe without managing files by hand, set a MaxMind
licence key and let Raiwall fetch the databases at startup:

```bash
export RAIWALL_GEOIP_LICENSE_KEY=your_maxmind_key   # or RAIWALL_GEOIP_LICENSE_KEY_FILE
raiwall run --config /etc/raiwall/raiwall.yaml
```

`GET /.raiwall/api/v1/telemetry/geoip` reports which databases are loaded
(`country_db`, `city_db`, `asn_db`); the dashboard uses it to explain an empty
country breakdown instead of silently rendering a bare globe.

### `declarative`

| Key | Default | Notes |
| :--- | :--- | :--- |
| `mode` | `sync` when resources exist, else `off` | `off`, `seed`, `sync` |
| `prune` | `false` | Requires `mode: sync` |
| `strict` | `false` | Abort on conflicts with API-managed records |

---

## 5. Declarative resources

Declared objects receive deterministic IDs (`cfg:<kind>:<name>`) and are
reconciled into the control store at boot:

| Mode | Behaviour |
| :--- | :--- |
| `off` | File resources are ignored; the dashboard owns everything |
| `seed` | Create missing records only; UI edits survive |
| `sync` | Upsert every declared record; UI edits are overwritten |
| `prune: true` | Delete file-managed records no longer declared (sync only) |
| `strict: true` | Abort startup on conflicts with API-managed records |

File-managed records are returned with `managed: true` and mutating requests
through the dashboard/REST API return **409 Conflict**. A new snapshot is only
deployed when the compiled content hash changes.

### `applications[]`

| Key | Notes |
| :--- | :--- |
| `name` | Slug, unique |
| `hostnames` | Exact, wildcard (`*.example.com`), or `*`; unique across apps |
| `mode` | Defaults to `waf.mode` |
| `routing_type` | `proxy`, `static`, `redirect` |
| `document_root` | Required for `static` |
| `redirect_url`, `redirect_status` | Required for `redirect`; 301/302/307/308 |
| `upstreams[]` | `dial`, `weight`, `max_fails`, `fail_timeout`, `health_check_path`, `health_check_interval` |
| `load_balancing` | `round_robin`, `least_conn`, `ip_hash`, `primary_backup` |
| `ssl_mode` | `none`, `auto`, `manual` |
| `certificate` | Required for `manual` |
| `ports[]` | `port`, `scheme` (`http`/`https`) metadata |
| `proxy` | `client_ip_source`, `rewrite_xff`, `hsts`, `enable_sse`, `enable_compression`, `enable_ipv6`, `redirect_http` |
| `custom_headers` | Map of response headers |
| `auth` | `enabled`, `bypass_paths` |
| `forwarding[]` | `prefix`, `upstreams`, `strip_prefix`, `host_header_override`, `comment` |
| `semantic_policy` | Per-module override: `strict`, `balance`, `audit`, `disabled` |
| `block_status_code`, `block_response_body`, `offline_status_code`, `offline_response_body` | Per-app overrides |

### `certificates[]`

| Key | Notes |
| :--- | :--- |
| `name` | Slug, unique |
| `domains` | SANs |
| `source` | `self-signed`, `upload`, `acme` |
| `cert_pem`, `key_pem` | Required for `upload`; AES-256-GCM sealed at rest |
| `auto_renew` | Renew inside the expiry window |
| `acme_staging` | Use the staging CA |

### `acls[]`

| Key | Notes |
| :--- | :--- |
| `name` | Slug, unique |
| `expression` | `expr` expression, e.g. `has_prefix(path, '/admin') && !in_ip_group(client_ip, 'private')` |
| `action` | `allow`, `block`, `challenge`, `redirect`, `audit` |
| `priority` | Lower runs first |
| `status_code` | 200–599 |
| `redirect_url` | Required for `redirect` |
| `enabled` | Defaults to `true` |

Available helpers include `in_ip_group(ip, name)`, `in_feed(ip, name)`,
`has_prefix`, `has_suffix`, `contains`, and GeoIP fields.

### `exceptions[]`

Parameter-level false-positive bypass. At least one of `path`, `path_prefix`,
or `path_regex` is required.

| Key | Notes |
| :--- | :--- |
| `host`, `path`, `path_prefix`, `path_regex` | Request matching |
| `method` | `GET`, `POST`, … |
| `location` | `query`, `body`, `header`, `cookie`, `path` |
| `param_name`, `param_regex` | `*` matches every parameter |
| `rule_id` | `*` matches every rule |
| `enabled` | Defaults to `true` |

### `ip_groups[]`

| Key | Notes |
| :--- | :--- |
| `name` | Slug, unique |
| `entries[].cidr` | Valid CIDR |
| `entries[].comment` | Free text |

### `rate_policies[]`

Per-host tiered limits: `name`, `host` (`*` for global), `tier1_*`, `tier2_*`,
`tier3_*`, `waiting_room_enabled`, `waiting_room_capacity`,
`waiting_room_paths`.

### `bot_policies[]`

Per-host bot overrides: `name`, `host` (`*` for global), `pow_enabled`,
`pow_difficulty` (1,000–200,000 when enabled), `trap_urls`.

### `identity_providers[]`

`name`, `type` (`oidc`, `ldap`, `github`), `enabled`, and a free-form `config`
map (for example `issuer_url`, `client_id`, `client_secret`, `redirect_url`,
`scopes`).

### `templates[]`

Response pages keyed by status code: `name`, `status_code`, `title`,
`content_html`, `custom_css`, `brand_name`, `logo_url`. Placeholders:
`{{.EventID}}`, `{{.ClientIP}}`, `{{.Timestamp}}`, `{{.Host}}`, `{{.Path}}`,
`{{.BrandName}}`, `{{.LogoURL}}`, `{{.StatusCode}}`, `{{.StatusText}}`,
`{{.Details}}`.

### `detector`

| Key | Notes |
| :--- | :--- |
| `modules.<name>` | `disabled`, `audit`, `balance`, `strict` |
| `inner_rules_disabled[]` | Virtual-patch rule IDs to disable |

Module names: `sql_inj`, `xss`, `file_upload`, `file_include`, `cmd_inj`,
`java_code_inj`, `java_deserialization`, `php_deserialization`, `php_code_inj`,
`asp_code_inj`, `ssti`, `csrf`, `ssrf`, `mal_http`.

---

## 6. Validate and inspect

```bash
raiwall config validate --config config/raiwall.yaml
raiwall config print    --config config/raiwall.yaml   # adapted Caddy JSON
raiwall config validate                                # discovered path
```

`config validate` reports every problem in one pass (duplicate names, unknown
store references, invalid CIDRs, missing upstreams, and so on). `config print`
shows exactly what the gateway will run.

---

## 7. Deployment mapping

### Docker Compose

`docker-compose.yml` mounts `./config/raiwall.yaml` read-only at
`/etc/raiwall/raiwall.yaml` and supplies only secrets and deployment values
through `.env` (see `.env.example`). The bundled stack also starts a
`postgres:18-alpine` service, a demo `upstream:80` nginx service, and points
`RAIWALL_DATABASE_URL` at PostgreSQL.

### Helm

`deploy/helm/raiwall/values.yaml#config` mirrors the schema 1:1 and is rendered
verbatim into a ConfigMap. Secrets are never placed in the ConfigMap:

- Chart-managed Secret (`secrets.hmacSecret`, `secrets.powSecret`,
  `secrets.adminPassword`, `secrets.sessionSecret`, `secrets.alertWebhook`).
  Empty HMAC/PoW/session values are generated once and preserved across
  upgrades.
- Existing Secret (`secrets.existingSecret`) containing the `RAIWALL_*` keys.
- Database DSN from `database.*`, or from `database.existingSecret` +
  `database.urlKey`.

The chart always targets an **external PostgreSQL** instance; it does not
bundle a database subchart. ConfigMap/Secret changes restart the pod through the
`checksum/config` and `checksum/secret` annotations.

---

## 8. Migrating from a Caddyfile

The Caddyfile adapter and `raiwall { … }` directive parser have been removed.
Translate the global options and the single shared handler block:

| Caddyfile | raiwall.yaml |
| :--- | :--- |
| `admin off` | `caddy.admin.listen: "off"` |
| `auto_https off` | `server.auto_https: false` |
| `storage file_system /var/lib/raiwall/certmagic` | `caddy.storage.module: file_system`, `caddy.storage.root: …` |
| `:8080 { … }` | `server.http.listen: ":8080"` |
| `:8443 { tls { get_certificate raiwall } }` | `server.https.listen: ":8443"` + `certificates:` entries |
| `raiwall { mode defense }` | `waf.mode: defense` |
| `block_status 403` | `waf.block_status_code: 403` |
| `offline_status 503` | `waf.offline_status_code: 503` |
| `control { db_path … }` | `storage.database_url: …` |
| `control { hmac_secret … }` | `control.hmac_secret: …` |
| `storage { store "pg" { driver postgres dsn "…" } control pg }` | `storage.stores.pg: { driver: postgres, dsn: "…" }`, `storage.control: pg` |
| `sidecar { listen :50051 }` | `sidecar: { enabled: true, listen: ":50051" }` |
| Per-site `tls { get_certificate raiwall }` | `applications[].ssl_mode: auto` or `manual` + `certificate` |

Per-application behavior that used to live in separate Caddyfile site blocks
(upstreams, headers, auth, forwarding) now belongs under `applications[]`.

---

## 9. Common validation errors

| Message | Fix |
| :--- | :--- |
| `storage.database_url and storage.stores are mutually exclusive` | Keep one storage style |
| `storage.control references unknown store "x"` | Declare `stores.x` or fix the role binding |
| `applications[i] hostname "x" is already declared by applications[j]` | Hostnames must be unique |
| `applications[i].certificate is required when ssl_mode is manual` | Reference a `certificates[]` entry |
| `declarative.prune requires declarative.mode: sync` | Set `mode: sync` or disable prune |
| `waf.ast_timeout must be between 1ms and 5ms` | Lower the timeout; the 5ms cap is a hard constraint |
| `rate_limit.storage_addr is required when rate_limit.storage is redis` | Provide `host:port` |
| `config … contains inline secrets (…) and security.strict_secrets is enabled` | Move values to `${ENV}` or `*_FILE` |
