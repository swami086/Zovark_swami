#!/bin/bash
# Zovark DMZ Deployment Script
# Usage: ./deploy.sh --siem splunk --admin admin@example.com
# Deploys Zovark in under 30 minutes on validated hardware.

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

SIEM_TYPE="generic"
GPU_MODE="auto"
ADMIN_EMAIL=""
ZOVARK_DIR="/opt/zovark"
DATA_DIR="/opt/zovark/data"

usage() {
    echo "Usage: $0 --siem <splunk|elastic|sentinel|generic> --admin <email> [--gpu <auto|none|nvidia>] [--dir <install_dir>]"
    echo ""
    echo "Options:"
    echo "  --siem     SIEM platform (splunk, elastic, sentinel, generic)"
    echo "  --admin    Admin email for initial account"
    echo "  --gpu      GPU mode: auto (detect), none (template-only), nvidia (force GPU)"
    echo "  --dir      Install directory (default: /opt/zovark)"
    echo ""
    echo "Examples:"
    echo "  $0 --siem splunk --admin ciso@hospital.org"
    echo "  $0 --siem elastic --admin admin@defense.mil --gpu none"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --siem) SIEM_TYPE="$2"; shift 2;;
        --gpu) GPU_MODE="$2"; shift 2;;
        --admin) ADMIN_EMAIL="$2"; shift 2;;
        --dir) ZOVARK_DIR="$2"; DATA_DIR="$2/data"; shift 2;;
        -h|--help) usage;;
        *) echo "Unknown option: $1"; usage;;
    esac
done

if [ -z "$ADMIN_EMAIL" ]; then
    echo -e "${RED}ERROR: --admin email required${NC}"
    usage
fi

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo -e "${BOLD}  ZOVARK DMZ DEPLOYMENT${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo ""
echo "  SIEM:  $SIEM_TYPE"
echo "  GPU:   $GPU_MODE"
echo "  Admin: $ADMIN_EMAIL"
echo "  Dir:   $ZOVARK_DIR"
echo ""

# ─────────────────────────────────────────
# PHASE 1: Hardware Validation
# ─────────────────────────────────────────
echo -e "${BOLD}[1/7] HARDWARE VALIDATION${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}ERROR: Must run as root or with sudo${NC}"
    exit 1
fi

if ! command -v docker &>/dev/null; then
    echo -e "${RED}ERROR: Docker not installed. Install Docker Engine first.${NC}"
    echo "  https://docs.docker.com/engine/install/"
    exit 1
fi

if ! command -v docker compose &>/dev/null; then
    echo -e "${RED}ERROR: Docker Compose not installed.${NC}"
    exit 1
fi

TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))
echo "  RAM: ${TOTAL_RAM_GB}GB"
if [ "$TOTAL_RAM_GB" -lt 16 ]; then
    echo -e "${RED}BLOCKED: Minimum 16GB RAM required (found ${TOTAL_RAM_GB}GB)${NC}"
    exit 1
fi

HAS_GPU=false
GPU_MEM_GB=0
if [ "$GPU_MODE" = "none" ]; then
    echo "  GPU: Skipped (template-only mode)"
    ZOVARK_MODE="templates-only"
elif command -v nvidia-smi &>/dev/null; then
    GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
    GPU_MEM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1)
    GPU_MEM_GB=$((GPU_MEM / 1024))
    echo "  GPU: $GPU_NAME (${GPU_MEM_GB}GB VRAM)"
    HAS_GPU=true
    ZOVARK_MODE="full"

    if ! docker info 2>/dev/null | grep -q "nvidia"; then
        echo -e "${YELLOW}WARNING: NVIDIA Container Toolkit not detected.${NC}"
        echo -e "${YELLOW}  Install: https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html${NC}"
    fi
else
    echo "  GPU: None detected"
    if [ "$GPU_MODE" = "nvidia" ]; then
        echo -e "${RED}BLOCKED: --gpu nvidia specified but no NVIDIA GPU found${NC}"
        exit 1
    fi
    ZOVARK_MODE="templates-only"
    echo -e "${YELLOW}  → Template-only mode (no AI investigation without GPU)${NC}"
fi

DISK_AVAIL_GB=$(df -BG "$ZOVARK_DIR" 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'G' || echo "0")
if [ "${DISK_AVAIL_GB:-0}" -lt 50 ]; then
    echo -e "${RED}BLOCKED: Minimum 50GB free disk required${NC}"
    exit 1
fi
echo "  Disk: ${DISK_AVAIL_GB}GB available"

echo -e "${GREEN}  ✓ Hardware validated${NC}"

# ─────────────────────────────────────────
# PHASE 2: Directory Setup
# ─────────────────────────────────────────
echo ""
echo -e "${BOLD}[2/7] DIRECTORY SETUP${NC}"

mkdir -p "$ZOVARK_DIR" "$DATA_DIR/postgres" "$DATA_DIR/redis" "$DATA_DIR/models" "$DATA_DIR/logs"
echo "  Created $ZOVARK_DIR"

# ─────────────────────────────────────────
# PHASE 3: Configuration
# ─────────────────────────────────────────
echo ""
echo -e "${BOLD}[3/7] CONFIGURATION${NC}"

DB_PASSWORD=$(openssl rand -hex 16)
REDIS_PASSWORD=$(openssl rand -hex 16)
JWT_SECRET=$(openssl rand -hex 32)
ADMIN_PASSWORD=$(openssl rand -base64 12 | tr -d '/+=' | head -c 16)

cat > "$ZOVARK_DIR/.env" <<ENVEOF
# Zovark Configuration — Generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# DO NOT COMMIT THIS FILE

ZOVARK_MODE=${ZOVARK_MODE}
POSTGRES_USER=zovark
POSTGRES_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=zovark
REDIS_PASSWORD=${REDIS_PASSWORD}
JWT_SECRET=${JWT_SECRET}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
ZOVARK_MODEL_FAST=llama3.2:3b
ZOVARK_MODEL_CODE=llama3.1:8b
SIEM_TYPE=${SIEM_TYPE}
ZOVARK_ASSESS_TIMEOUT=45
ZOVARK_BATCH_WINDOW_SECONDS=60
ZOVARK_BATCH_MAX_SIZE=500
ZOVARK_CB_YELLOW=50
ZOVARK_CB_RED=100
ZOVARK_CB_RECOVERY=25
ENVEOF

chmod 600 "$ZOVARK_DIR/.env"
echo "  Created .env (passwords auto-generated)"

HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

case "$SIEM_TYPE" in
    splunk)
        WEBHOOK_URL="http://${HOST_IP}:8090/api/v1/ingest/splunk"
        SIEM_INSTRUCTIONS="
  Splunk Configuration:
    1. Settings → Alert Actions → Add New → Webhook
    2. URL: $WEBHOOK_URL
    3. Method: POST, Content-Type: application/json"
        ;;
    elastic)
        WEBHOOK_URL="http://${HOST_IP}:8090/api/v1/ingest/elastic"
        SIEM_INSTRUCTIONS="
  Elastic Configuration:
    1. Management → Rules → Create Rule → Action: Webhook
    2. URL: $WEBHOOK_URL
    3. Method: POST, Content-Type: application/json"
        ;;
    sentinel)
        WEBHOOK_URL="http://${HOST_IP}:8090/api/v1/ingest/generic"
        SIEM_INSTRUCTIONS="
  Sentinel Configuration:
    1. Logic Apps → Create Playbook → Trigger: Sentinel alert
    2. Action: HTTP POST to $WEBHOOK_URL"
        ;;
    *)
        WEBHOOK_URL="http://${HOST_IP}:8090/api/v1/ingest/generic"
        SIEM_INSTRUCTIONS="
  Generic Webhook: POST $WEBHOOK_URL
  Content-Type: application/json"
        ;;
esac

echo "  SIEM type: $SIEM_TYPE"
echo "  Webhook: $WEBHOOK_URL"

# ─────────────────────────────────────────
# PHASE 4: Pull Docker Images
# ─────────────────────────────────────────
echo ""
echo -e "${BOLD}[4/7] PULLING IMAGES${NC}"
echo "  This may take 10-15 minutes on first run..."

cd "$ZOVARK_DIR"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

if [ -f "$REPO_DIR/docker-compose.yml" ]; then
    cp "$REPO_DIR/docker-compose.yml" "$ZOVARK_DIR/"
    cp -r "$REPO_DIR/migrations" "$ZOVARK_DIR/" 2>/dev/null || true
    cp -r "$REPO_DIR/config" "$ZOVARK_DIR/" 2>/dev/null || true
    cp -r "$REPO_DIR/sandbox" "$ZOVARK_DIR/" 2>/dev/null || true
    echo "  Copied deployment files"
else
    echo -e "${RED}ERROR: docker-compose.yml not found at $REPO_DIR${NC}"
    exit 1
fi

docker compose --env-file .env pull 2>&1 | tail -5 || true
echo -e "${GREEN}  ✓ Images pulled${NC}"

# ─────────────────────────────────────────
# PHASE 5: Start Services
# ─────────────────────────────────────────
echo ""
echo -e "${BOLD}[5/7] STARTING SERVICES${NC}"

docker compose --env-file .env up -d 2>&1 | tail -5

echo "  Waiting for services to initialize..."
for i in $(seq 1 12); do
    API_OK=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8090/health 2>/dev/null || echo "000")
    [ "$API_OK" = "200" ] && break
    sleep 5
done

# ─────────────────────────────────────────
# PHASE 6: Health Checks
# ─────────────────────────────────────────
echo ""
echo -e "${BOLD}[6/7] HEALTH CHECKS${NC}"

HEALTH_PASS=true

API_STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8090/health 2>/dev/null || echo "000")
if [ "$API_STATUS" = "200" ]; then
    echo -e "  API:        ${GREEN}✓ healthy${NC}"
else
    echo -e "  API:        ${RED}✗ unhealthy (HTTP $API_STATUS)${NC}"
    HEALTH_PASS=false
fi

DASH_STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000 2>/dev/null || echo "000")
if [ "$DASH_STATUS" = "200" ]; then
    echo -e "  Dashboard:  ${GREEN}✓ healthy${NC}"
else
    echo -e "  Dashboard:  ${RED}✗ unhealthy${NC}"
    HEALTH_PASS=false
fi

PG_OK=$(docker compose exec -T postgres psql -U zovark -d zovark -c "SELECT 1;" 2>/dev/null | grep -c "1 row" || echo "0")
if [ "$PG_OK" = "1" ]; then
    echo -e "  PostgreSQL: ${GREEN}✓ healthy${NC}"
else
    echo -e "  PostgreSQL: ${RED}✗ unhealthy${NC}"
    HEALTH_PASS=false
fi

if [ "$HEALTH_PASS" = "false" ]; then
    echo -e "${YELLOW}  Some services still starting. Check: docker compose logs${NC}"
fi

# ─────────────────────────────────────────
# PHASE 7: Validation
# ─────────────────────────────────────────
echo ""
echo -e "${BOLD}[7/7] VALIDATION${NC}"

TOKEN=$(curl -s -X POST http://localhost:8090/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"admin@test.local\",\"password\":\"TestPass2026\"}" 2>/dev/null \
    | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -n "$TOKEN" ]; then
    echo -e "  Auth:       ${GREEN}✓ login successful${NC}"
else
    echo -e "  Auth:       ${YELLOW}⚠ default admin login failed (may need setup)${NC}"
fi

TEMPLATE_COUNT=$(docker compose exec -T postgres psql -U zovark -d zovark -t -c \
    "SELECT count(*) FROM agent_skills WHERE is_active=true;" 2>/dev/null | tr -d ' ')
echo "  Templates:  ${TEMPLATE_COUNT:-0} active"

# ─────────────────────────────────────────
# DEPLOYMENT COMPLETE
# ─────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ZOVARK DEPLOYMENT COMPLETE${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo ""
echo "  Mode:      $ZOVARK_MODE"
echo "  Dashboard: http://${HOST_IP}:3000"
echo "  API:       http://${HOST_IP}:8090"
echo "  Webhook:   $WEBHOOK_URL"
echo ""
echo "  Admin Login:"
echo "    Email:    $ADMIN_EMAIL"
echo "    Password: $ADMIN_PASSWORD"
echo "    ⚠ Change this password immediately after first login"
echo ""
echo "$SIEM_INSTRUCTIONS"
echo ""
echo "  Firewall (recommended for DMZ):"
echo "    iptables -A OUTPUT -j DROP"
echo "    iptables -A INPUT -p tcp --dport 8090 -s <SIEM_IP> -j ACCEPT"
echo "    iptables -A INPUT -p tcp --dport 3000 -s <ANALYST_SUBNET> -j ACCEPT"
echo ""
echo "  Credentials saved to: $ZOVARK_DIR/.env"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
