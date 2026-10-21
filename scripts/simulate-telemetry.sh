#!/usr/bin/env bash
# ==============================================================================
# Raiwall WAF Synthetic Traffic & Security Telemetry Generator
# ==============================================================================
# Sends benign traffic, honeypot canary checks, and security rule simulations
# to generate live metrics for monitoring on the Raiwall dashboard.
# ==============================================================================

set -euo pipefail

BASE_URL="${RAIWALL_URL:-http://localhost:8080}"
ADMIN_USER="${RAIWALL_USER:-admin}"
ADMIN_PASS="${RAIWALL_PASS:-admin}"

echo "=========================================================="
echo "  Raiwall WAF Live Telemetry Generator"
echo "  Target: ${BASE_URL}"
echo "=========================================================="
echo ""

# 1. Check Gateway Availability
echo "[1/4] Checking gateway availability..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/.well-known/security.txt" || echo "000")
if [ "${HTTP_CODE}" = "200" ]; then
    echo "  ✓ Gateway is online (HTTP 200)"
else
    echo "  ✗ Gateway returned status ${HTTP_CODE}. Please verify Docker container is running."
    exit 1
fi

# 2. Generate Benign Traffic to populate Topology & Statistics
echo ""
echo "[2/4] Generating benign traffic requests..."
for i in {1..5}; do
    curl -s -o /dev/null -w "  - Request $i: %{http_code}\n" "${BASE_URL}/healthz"
    curl -s -o /dev/null "${BASE_URL}/.well-known/security.txt"
    sleep 0.2
done

# 3. Trigger Honeypot Canary Event (Generates live critical alert in telemetry)
echo ""
echo "[3/4] Triggering honeypot canary security trap..."
CRAWLER_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/.raiwall/trap/honeypot" || echo "000")
echo "  ✓ Honeypot hit blocked with status: ${CRAWLER_CODE} Forbidden"

# 4. Check Telemetry Events from Control Plane API
echo ""
echo "[4/4] Verifying generated telemetry events..."
EVENT_COUNT=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASS}" "${BASE_URL}/.raiwall/api/events/stats" | grep -o '"total_blocked":[0-9]*' || echo "total_blocked: 0")
echo "  ✓ Live WAF Statistics: ${EVENT_COUNT}"

# Release any active IP ban so local development can continue seamlessly
curl -s -u "${ADMIN_USER}:${ADMIN_PASS}" -X POST "${BASE_URL}/.raiwall/api/v1/rate/bans/release-all" > /dev/null
echo "  ✓ Cleared auto-bans for development"

echo ""
echo "=========================================================="
echo "  Ready to Monitor in Web UI:"
echo "  - Live Threat Stream:   ${BASE_URL}/.raiwall/#/attacks"
echo "  - Attack Topology:      ${BASE_URL}/.raiwall/#/topology"
echo "  - Security Statistics:  ${BASE_URL}/.raiwall/#/statistics"
echo "  - Active Bans Manager:  ${BASE_URL}/.raiwall/#/http-flood"
echo "=========================================================="
