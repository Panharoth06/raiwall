#!/usr/bin/env bash
# ==============================================================================
# OWASP Core Rule Set (CRS) - FTW Test Runner
# ==============================================================================
# Executes official OWASP CRS regression tests using `go-ftw` against the
# reference CRS container (port 8090) or any target WAF.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRS_DIR="${SCRIPT_DIR}/coreruleset"
TESTS_DIR="${CRS_DIR}/tests/regression/tests"
FTW_BIN="$(go env GOPATH)/bin/go-ftw"

TARGET_PORT=8090
RULE_FILTER=""
SHOW_ALL=false

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --target [crs|raiwall|<port>]   Target WAF port (crs=8090, raiwall=8080) [default: crs]"
    echo "  --rule <regex>                 Filter tests by Rule ID regex (e.g. 942 for SQLi, 941 for XSS)"
    echo "  --all                          Run the entire regression test suite (1000+ tests)"
    echo "  -h, --help                     Show this help message"
    echo ""
    echo "Common Rule Families:"
    echo "  913 - Scanner Detection        920 - Protocol Enforcement"
    echo "  930 - LFI / Path Traversal     931 - RFI (Remote File Inclusion)"
    echo "  932 - Remote Code Execution    933 - PHP Application Attack"
    echo "  941 - XSS Injection            942 - SQL Injection"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)
            if [[ "$2" == "crs" ]]; then
                TARGET_PORT=8090
            elif [[ "$2" == "raiwall" ]]; then
                TARGET_PORT=8080
            else
                TARGET_PORT="$2"
            fi
            shift 2
            ;;
        --rule)
            RULE_FILTER="$2"
            shift 2
            ;;
        --all)
            SHOW_ALL=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown argument: $1"
            usage
            ;;
    esac
done

if [[ ! -f "$FTW_BIN" ]]; then
    echo "go-ftw binary not found at $FTW_BIN. Installing now..."
    go install github.com/coreruleset/go-ftw@latest
fi

if [[ ! -d "$TESTS_DIR" ]]; then
    echo "CRS regression tests not found at $TESTS_DIR."
    echo "Cloning coreruleset repository..."
    git clone --depth 1 https://github.com/coreruleset/coreruleset.git "$CRS_DIR"
fi

# Generate temporary config override for target port
TMP_OVERRIDE=$(mktemp /tmp/ftw_override_XXXXXX.json)
trap 'rm -f "$TMP_OVERRIDE"' EXIT

cat <<EOF > "$TMP_OVERRIDE"
{
  "testoverride": {
    "input": {
      "dest_addr": "127.0.0.1",
      "port": ${TARGET_PORT}
    }
  }
}
EOF

echo "=========================================================="
echo "  OWASP CRS Test Runner (go-ftw)"
echo "  Target Port: ${TARGET_PORT}"
echo "=========================================================="

FTW_ARGS=(
    "run"
    "-d" "$TESTS_DIR"
    "--overrides" "$TMP_OVERRIDE"
    "--cloud"
)

if [[ -n "$RULE_FILTER" ]]; then
    echo "  Rule Filter: ^${RULE_FILTER}"
    FTW_ARGS+=("-i" "^${RULE_FILTER}")
elif [[ "$SHOW_ALL" = false ]]; then
    # Default: Run standard SQLi rule 942100 if no rule is specified
    echo "  Default filter: ^942100 (SQLi). Use --all or --rule <id> for other rules."
    FTW_ARGS+=("-i" "^942100")
fi

echo "=========================================================="
cd "$SCRIPT_DIR"
"$FTW_BIN" "${FTW_ARGS[@]}"
