# Raiwall Helm chart

Deploys the Raiwall single-binary gateway (Caddy data plane, WAF engine, REST
API, and embedded Vue dashboard) with an **external PostgreSQL** database.

## Install

```bash
helm install raiwall deploy/helm/raiwall \
  --namespace raiwall --create-namespace \
  --set database.host=postgres.internal \
  --set database.password='...' \
  --set secrets.adminPassword='...'
```

`values.yaml#config` is a 1:1 mirror of the canonical `raiwall.yaml` schema.
Declare applications and policies there, exactly as in `config/raiwall.yaml`:

```yaml
config:
  applications:
    - name: portal
      hostnames: ["portal.example.com"]
      mode: defense
      upstreams:
        - dial: "10.0.0.10:8080"
  acls:
    - name: block_admin_from_public
      expression: "has_prefix(path, '/admin') && !in_ip_group(client_ip, 'private_networks')"
      action: block
```

## Secrets

The chart never renders secrets into the ConfigMap. Two options:

1. **Chart-managed Secret** (default): set `secrets.hmacSecret`,
   `secrets.powSecret`, `secrets.adminPassword`, `secrets.sessionSecret`.
   Empty HMAC/PoW/session values are generated once and preserved across
   upgrades. An empty admin password is omitted so the application generates one
   and logs it once at WARN level.
2. **Existing Secret**: set `secrets.existingSecret` to a Secret containing
   `RAIWALL_HMAC_SECRET`, `RAIWALL_POW_SECRET`, `RAIWALL_ADMIN_PASSWORD`, and
   `RAIWALL_DATABASE_URL` (unless `database.existingSecret` is set).

For database credentials with special characters, store the complete DSN in a
Secret and set `database.existingSecret` + `database.urlKey`.

## Production notes

- Run with `replicaCount >= 2` and `podDisruptionBudget.enabled=true`. Rate
  limiting state is per process unless `config.rate_limit.storage=redis`.
- `persistence.enabled=true` keeps certmagic certificates and, when using the
  SQLite fallback, the control database. With PostgreSQL the volume only holds
  certificates.
- Probes use the unauthenticated `/.raiwall/api/openapi.json` endpoint.
- `securityContext.readOnlyRootFilesystem=true` is the default; `/tmp` and
  `/var/lib/raiwall` are mounted explicitly.

## Validate locally

```bash
helm lint deploy/helm/raiwall
helm template raiwall deploy/helm/raiwall --namespace raiwall > /tmp/raiwall.yaml
```
