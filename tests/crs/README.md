# CRS parity harness

Runs the official OWASP CRS regression suite against Raiwall in CRS **block**
mode (PL1) and enforces the TASKS.md 1A.5 thresholds:

- **Critical families** (`930` LFI, `932` RCE, `941` XSS, `942` SQLi): zero
  failures among applicable tests.
- **Overall**: at least 95% of applicable tests pass.

## What it does

`run.sh`:

1. Reads the corpus from `RAIWALL_CRS_TESTS`, else `test-lab/coreruleset`,
   else clones the pinned `v4.30.0` tag (the version embedded in the binary).
2. Builds `raiwall`, a local echo upstream, and the gate from source.
3. Starts the upstream on `127.0.0.1:19090` and Raiwall on `127.0.0.1:18080`
   using `raiwall.yaml` (CRS block, PL1, no bot/rate interference).
4. Runs `go-ftw` in cloud/status mode with JSON output (the regression corpus
   asserts status codes, not rule IDs) for the critical subset and the full
   suite.
5. Applies `skips.txt` exclusions and enforces both thresholds.

`go-ftw` cannot attribute a block to a specific rule in cloud mode. This gate
therefore measures **block/allow parity**; per-rule attribution stays in the
unit suite (`internal/core/waf/crs`).

## Usage

```bash
# Local (uses test-lab/coreruleset when present; no Docker required)
./tests/crs/run.sh

# CI / pinned corpus and artifact capture
RAIWALL_CRS_TESTS=/path/to/tests ARTIFACTS_DIR=/tmp/crs ./tests/crs/run.sh

# Narrow a run while debugging
CRITICAL_INCLUDE='^942' RAIWALL_CRS_PORT=18080 ./tests/crs/run.sh
```

Environment:

| Variable | Default | Purpose |
|---|---|---|
| `RAIWALL_CRS_TESTS` | auto | Path to `tests/regression/tests` |
| `CRS_VERSION` | `v4.30.0` | Corpus tag cloned when none is local |
| `RAIWALL_CRS_PORT` | `18080` | Raiwall listener |
| `RAIWALL_CRS_UPSTREAM_PORT` | `19090` | Echo upstream |
| `CRITICAL_INCLUDE` | `^(930\|932\|941\|942)` | Critical go-ftw include regex |
| `MIN_OVERALL` | `95` | Overall pass threshold |
| `ARTIFACTS_DIR` | unset | Copy reports and the Raiwall log here |

## Skips

`skips.txt` holds Go regexes matched against go-ftw test IDs. The only current
entry excludes response-rule tests (`^95…`) because response inspection is
TASKS.md 1B.1. Add entries only with a reason; a growing skip list is a
regression signal, not a fix.

## CI

`.github/workflows/crs-parity.yml` runs this on a nightly schedule, on changes
to the WAF/CRS code, and on manual dispatch. It uploads the reports as
artifacts.
