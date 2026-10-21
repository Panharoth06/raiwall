#!/usr/bin/env bash
# ==============================================================================
# WAF Attack Testing Suite (OWASP CRS & Raiwall)
# ==============================================================================
# Sends simulated web attacks and benign traffic against the target WAF(s)
# and evaluates blocking efficacy (HTTP 403 Forbidden vs HTTP 200 OK).
# ==============================================================================

set -uo pipefail

CRS_URL="http://localhost:8090"
RAIWALL_URL="http://localhost:8080"
TARGET="all"

# ANSI color codes
C_RESET="\033[0m"
C_BOLD="\033[1m"
C_RED="\033[31m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_CYAN="\033[36m"
C_GRAY="\033[90m"

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --target [crs|raiwall|all]   Target WAF to test (default: all)"
    echo "  --crs-url <url>              CRS WAF URL (default: http://localhost:8090)"
    echo "  --raiwall-url <url>          Raiwall WAF URL (default: http://localhost:8080)"
    echo "  -h, --help                   Show this help message"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --crs-url) CRS_URL="$2"; shift 2 ;;
        --raiwall-url) RAIWALL_URL="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown parameter: $1"; usage ;;
    esac
done

echo -e "${C_BOLD}${C_CYAN}======================================================================${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}                WAF Testing Suite & Benchmark                         ${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}======================================================================${C_RESET}"
echo -e "${C_GRAY}Target mode : ${TARGET}${C_RESET}"
if [[ "$TARGET" == "all" || "$TARGET" == "crs" ]]; then
    echo -e "${C_GRAY}CRS Target  : ${CRS_URL}${C_RESET}"
fi
if [[ "$TARGET" == "all" || "$TARGET" == "raiwall" ]]; then
    echo -e "${C_GRAY}Raiwall     : ${RAIWALL_URL}${C_RESET}"
fi
echo ""

send_req() {
    local base_url="$1"
    local method="$2"
    local path="$3"
    local user_agent="${4:-Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)}"
    local data="${5:-}"

    if [[ -n "$data" ]]; then
        curl -s -o /dev/null -w "%{http_code}:%{time_total}" \
            -X "$method" \
            -H "User-Agent: $user_agent" \
            -H "Content-Type: application/json" \
            -H "Accept: application/json" \
            -d "$data" \
            "${base_url}${path}" || echo "000:0.000"
    else
        curl -s -o /dev/null -w "%{http_code}:%{time_total}" \
            -X "$method" \
            -H "User-Agent: $user_agent" \
            -H "Accept: application/json" \
            "${base_url}${path}" || echo "000:0.000"
    fi
}

run_test_case() {
    local category="$1"
    local name="$2"
    local expected="$3" # "BLOCK" or "ALLOW"
    local method="$4"
    local path="$5"
    local ua="$6"
    local data="$7"

    printf "${C_BOLD}%-14s${C_RESET} | %-38s " "[$category]" "$name"

    if [[ "$TARGET" == "crs" || "$TARGET" == "all" ]]; then
        local res_crs
        res_crs=$(send_req "$CRS_URL" "$method" "$path" "$ua" "$data")
        local code_crs="${res_crs%%:*}"
        local time_crs="${res_crs##*:}"

        local crs_status
        if [[ "$expected" == "BLOCK" ]]; then
            if [[ "$code_crs" == "403" || "$code_crs" == "400" ]]; then
                crs_status="${C_GREEN}BLOCKED (${code_crs})${C_RESET}"
            else
                crs_status="${C_RED}BYPASSED (${code_crs})${C_RESET}"
            fi
        else
            if [[ "$code_crs" == "200" || "$code_crs" == "201" || "$code_crs" == "204" ]]; then
                crs_status="${C_GREEN}ALLOWED (${code_crs})${C_RESET}"
            else
                crs_status="${C_YELLOW}FLAGGED (${code_crs})${C_RESET}"
            fi
        fi
        printf "| CRS: %-22b " "$crs_status"
    fi

    if [[ "$TARGET" == "raiwall" || "$TARGET" == "all" ]]; then
        local res_rw
        res_rw=$(send_req "$RAIWALL_URL" "$method" "$path" "$ua" "$data")
        local code_rw="${res_rw%%:*}"
        local time_rw="${res_rw##*:}"

        local rw_status
        if [[ "$expected" == "BLOCK" ]]; then
            if [[ "$code_rw" == "403" || "$code_rw" == "400" || "$code_rw" == "468" ]]; then
                rw_status="${C_GREEN}BLOCKED (${code_rw})${C_RESET}"
            else
                rw_status="${C_RED}BYPASSED (${code_rw})${C_RESET}"
            fi
        else
            if [[ "$code_rw" == "200" || "$code_rw" == "201" || "$code_rw" == "204" ]]; then
                rw_status="${C_GREEN}ALLOWED (${code_rw})${C_RESET}"
            else
                rw_status="${C_YELLOW}FLAGGED (${code_rw})${C_RESET}"
            fi
        fi
        printf "| Raiwall: %-22b" "$rw_status"
    fi

    printf "\n"
}

# --- 1. BENIGN TRAFFIC (Expect: ALLOW / 200) ---
echo -e "${C_BOLD}--- 1. Legitimate (Benign) Traffic Baseline ---${C_RESET}"
run_test_case "BENIGN" "Simple GET Root" "ALLOW" "GET" "/healthz" "" ""
run_test_case "BENIGN" "GET with query params" "ALLOW" "GET" "/public/search?q=wireless+headphones&page=2" "" ""
run_test_case "BENIGN" "POST valid JSON object" "ALLOW" "POST" "/public/feedback" "" '{"item_id": 42, "qty": 3, "notes": "Deliver at lobby"}'

echo ""
# --- 2. SQL INJECTION (Expect: BLOCK / 403) ---
echo -e "${C_BOLD}--- 2. SQL Injection (SQLi) Attacks ---${C_RESET}"
run_test_case "SQLi" "Classic Tautology (' OR 1=1--)" "BLOCK" "GET" "/public/items?id=1%27%20OR%201=1--" "" ""
run_test_case "SQLi" "Union-based Extraction" "BLOCK" "GET" "/public/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users--" "" ""
run_test_case "SQLi" "POST JSON Body SQLi" "BLOCK" "POST" "/public/login" "" '{"user": "admin", "pass": "'\'' OR '\''1'\''='\''1"}'
run_test_case "SQLi" "Stacked Query & Sleep" "BLOCK" "GET" "/public/data?id=10;%20WAITFOR%20DELAY%20%270:0:5%27--" "" ""

echo ""
# --- 3. CROSS-SITE SCRIPTING (Expect: BLOCK / 403) ---
echo -e "${C_BOLD}--- 3. Cross-Site Scripting (XSS) Attacks ---${C_RESET}"
run_test_case "XSS" "Standard <script> tag" "BLOCK" "GET" "/public/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E" "" ""
run_test_case "XSS" "Event handler onerror payload" "BLOCK" "GET" "/public/profile?bio=%3Cimg%20src=x%20onerror=alert(1)%3E" "" ""
run_test_case "XSS" "javascript: URI scheme" "BLOCK" "GET" "/public/redirect?url=javascript:alert(1)" "" ""
run_test_case "XSS" "SVG onload handler" "BLOCK" "POST" "/public/comment" "" '{"content": "<svg/onload=alert`xss`>"}'

echo ""
# --- 4. REMOTE CODE EXECUTION / SHELL INJECTION (Expect: BLOCK / 403) ---
echo -e "${C_BOLD}--- 4. Remote Code Execution (RCE) / Shell ---${C_RESET}"
run_test_case "RCE" "Semicolon shell separator" "BLOCK" "GET" "/public/ping?host=127.0.0.1;cat%20/etc/passwd" "" ""
run_test_case "RCE" "Pipe to id command" "BLOCK" "GET" "/public/lookup?ip=127.0.0.1|id" "" ""
run_test_case "RCE" "Backtick shell execution" "BLOCK" "GET" "/public/status?cmd=%60whoami%60" "" ""
run_test_case "RCE" "Subshell dollar syntax" "BLOCK" "POST" "/public/run" "" '{"arg": "$(uname -a)"}'

echo ""
# --- 5. PATH TRAVERSAL / LFI (Expect: BLOCK / 403) ---
echo -e "${C_BOLD}--- 5. Path Traversal & LFI Attacks ---${C_RESET}"
run_test_case "TRAVERSAL" "Dot-dot-slash /etc/passwd" "BLOCK" "GET" "/public/download?file=../../../../etc/passwd" "" ""
run_test_case "TRAVERSAL" "URL-encoded traversal (%2e%2e)" "BLOCK" "GET" "/public/view?doc=%2e%2e%2f%2e%2e%2fetc%2fpasswd" "" ""
run_test_case "TRAVERSAL" "Windows win.ini access" "BLOCK" "GET" "/public/file?name=..\\..\\windows\\win.ini" "" ""

echo ""
# --- 6. MALICIOUS SCANNERS & USER-AGENTS (Expect: BLOCK / 403) ---
echo -e "${C_BOLD}--- 6. Security Scanner & Bot Signatures ---${C_RESET}"
run_test_case "SCANNER" "sqlmap Automated Scanner" "BLOCK" "GET" "/public/test" "sqlmap/1.4.11#stable (http://sqlmap.org)" ""
run_test_case "SCANNER" "Nikto Web Vulnerability Scanner" "BLOCK" "GET" "/public/test" "Mozilla/5.0 (Nikto/2.1.6)" ""
run_test_case "SCANNER" "Acunetix Web Vulnerability Scanner" "BLOCK" "GET" "/public/test" "Acunetix-Product" ""

echo ""
echo -e "${C_BOLD}${C_CYAN}======================================================================${C_RESET}"
echo -e "${C_BOLD}${C_GREEN}Test suite completed!${C_RESET}"
echo -e "To inspect live CRS ModSecurity logs: ${C_YELLOW}tail -f test-lab/logs/error.log${C_RESET}"
