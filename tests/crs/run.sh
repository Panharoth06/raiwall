#!/usr/bin/env bash
# ==============================================================================
# OWASP CRS regression parity harness
# ==============================================================================
# Starts Raiwall in CRS block mode behind a local echo upstream and runs the
# official CRS regression suite with go-ftw (cloud/status mode), then enforces:
#   * zero failures in critical families (LFI, RCE, XSS, SQLi)
#   * >= 95% overall pass rate after documented skips
#
# Requirements: go, curl. The corpus is read from RAIWALL_CRS_TESTS when set,
# otherwise test-lab/coreruleset, otherwise a pinned clone of coreruleset.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CRS_VERSION="${CRS_VERSION:-v4.30.0}"
RAIWALL_PORT="${RAIWALL_CRS_PORT:-18080}"
UPSTREAM_PORT="${RAIWALL_CRS_UPSTREAM_PORT:-19090}"
CRITICAL_INCLUDE="${CRITICAL_INCLUDE:-^(930|932|941|942)}"
MIN_OVERALL="${MIN_OVERALL:-95}"
FTW_BIN="${FTW_BIN:-$(go env GOPATH)/bin/go-ftw}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/raiwall-crs.XXXXXX")"
RAIWALL_PID=""
UPSTREAM_PID=""

cleanup() {
    if [[ -n "${RAIWALL_PID}" ]]; then kill "${RAIWALL_PID}" 2>/dev/null || true; fi
    if [[ -n "${UPSTREAM_PID}" ]]; then kill "${UPSTREAM_PID}" 2>/dev/null || true; fi
    wait 2>/dev/null || true
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

log() { printf '==> %s\n' "$*"; }

# --- Corpus -----------------------------------------------------------------
if [[ -n "${RAIWALL_CRS_TESTS:-}" ]]; then
    TESTS_DIR="${RAIWALL_CRS_TESTS}"
elif [[ -d "${REPO_ROOT}/test-lab/coreruleset/tests/regression/tests" ]]; then
    TESTS_DIR="${REPO_ROOT}/test-lab/coreruleset/tests/regression/tests"
    log "using local corpus at ${TESTS_DIR} (version may differ from embedded CRS ${CRS_VERSION})"
else
    log "cloning coreruleset ${CRS_VERSION}"
    git clone --depth 1 --branch "${CRS_VERSION}" \
        https://github.com/coreruleset/coreruleset.git "${WORK_DIR}/coreruleset" >/dev/null 2>&1
    TESTS_DIR="${WORK_DIR}/coreruleset/tests/regression/tests"
fi
if [[ ! -d "${TESTS_DIR}" ]]; then
    echo "CRS regression tests not found at ${TESTS_DIR}" >&2
    exit 1
fi

# --- Tools ------------------------------------------------------------------
if [[ ! -x "${FTW_BIN}" ]]; then
    log "installing go-ftw v1.3.0"
    go install github.com/coreruleset/go-ftw@v1.3.0
fi

log "building raiwall, upstream, and gate"
(cd "${REPO_ROOT}" && go build -o "${WORK_DIR}/raiwall" ./cmd/raiwall)
(cd "${REPO_ROOT}" && go build -o "${WORK_DIR}/upstream" ./tests/crs/upstream)
(cd "${REPO_ROOT}" && go build -o "${WORK_DIR}/gate" ./tests/crs/gate)

# --- Run under test ---------------------------------------------------------
log "starting echo upstream on 127.0.0.1:${UPSTREAM_PORT}"
"${WORK_DIR}/upstream" "127.0.0.1:${UPSTREAM_PORT}" >"${WORK_DIR}/upstream.log" 2>&1 &
UPSTREAM_PID=$!

log "starting raiwall (CRS block, PL1) on 127.0.0.1:${RAIWALL_PORT}"
RAIWALL_DATABASE_URL="file:${WORK_DIR}/control.db?_pragma=busy_timeout(5000)" \
RAIWALL_CERTMAGIC_ROOT="${WORK_DIR}/certmagic" \
RAIWALL_LOG_LEVEL=error \
    "${WORK_DIR}/raiwall" run --config "${SCRIPT_DIR}/raiwall.yaml" \
    >"${WORK_DIR}/raiwall.log" 2>&1 &
RAIWALL_PID=$!

ready=0
for _ in $(seq 1 120); do
    if curl -fsS "http://127.0.0.1:${RAIWALL_PORT}/.raiwall/api/openapi.json" >/dev/null 2>&1; then
        ready=1
        break
    fi
    if ! kill -0 "${RAIWALL_PID}" 2>/dev/null; then
        echo "raiwall exited during startup:" >&2
        cat "${WORK_DIR}/raiwall.log" >&2
        exit 1
    fi
    sleep 0.5
done
if [[ "${ready}" -ne 1 ]]; then
    echo "raiwall did not become ready:" >&2
    cat "${WORK_DIR}/raiwall.log" >&2
    exit 1
fi

cat >"${WORK_DIR}/ftw.yaml" <<EOF
mode: cloud
testoverride:
  input:
    dest_addr: "127.0.0.1"
    port: ${RAIWALL_PORT}
EOF

EXCLUDE=""
if [[ -f "${SCRIPT_DIR}/skips.txt" ]]; then
    EXCLUDE="$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' "${SCRIPT_DIR}/skips.txt" | grep -v '^$' | paste -sd'|' - || true)"
fi
# Always pass an exclude flag: an empty array expansion is unsafe under
# `set -u` on macOS's bash 3.2, and ^$ matches no test ID.
EXCLUDE_ARGS=(-e "(${EXCLUDE:-^$})")

run_ftw() {
    local report="$1"
    shift
    log "go-ftw $*"
    set +e
    "${FTW_BIN}" run -d "${TESTS_DIR}" --config "${WORK_DIR}/ftw.yaml" --cloud -o json "${EXCLUDE_ARGS[@]}" "$@" \
        -f "${report}" >"${WORK_DIR}/ftw-stdout.log" 2>&1
    set -e
    # go-ftw exits non-zero when tests fail; the gate decides whether that is
    # within the accepted threshold.
}

status=0

# One go-ftw run feeds both gates: the critical view is a filtered slice of the
# same report (go-ftw forbids combining --include with --exclude).
run_ftw "${WORK_DIR}/full.txt"
if ! "${WORK_DIR}/gate" --report "${WORK_DIR}/full.txt" \
    --include-ids "${CRITICAL_INCLUDE}" --require-zero-failures \
    --label "CRS critical (LFI/RCE/XSS/SQLi)"; then
    status=1
fi
if ! "${WORK_DIR}/gate" --report "${WORK_DIR}/full.txt" \
    --min-overall "${MIN_OVERALL}" --label "CRS overall"; then
    status=1
fi

if [[ -n "${ARTIFACTS_DIR:-}" ]]; then
    mkdir -p "${ARTIFACTS_DIR}"
    cp "${WORK_DIR}/full.txt" "${ARTIFACTS_DIR}/"
    cp "${WORK_DIR}/raiwall.log" "${ARTIFACTS_DIR}/raiwall.log"
    log "artifacts written to ${ARTIFACTS_DIR}"
fi

if [[ "${status}" -ne 0 ]]; then
    echo "CRS parity gate failed" >&2
    exit 1
fi
echo "CRS parity gate passed"
