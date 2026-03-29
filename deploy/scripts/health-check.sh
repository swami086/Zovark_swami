#!/bin/bash
# ============================================================
# Zovark Health Check
# Checks status of all services
# ============================================================
set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DEPLOY_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== Zovark Health Check ==="
echo ""

# Docker services
echo "Services:"
docker compose -f docker-compose.production.yml ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null || \
    docker compose -f docker-compose.production.yml ps

echo ""

# API health
echo -n "API: "
if curl -sf http://localhost:${API_PORT:-8090}/health >/dev/null 2>&1; then
    echo -e "${GREEN}HEALTHY${NC}"
else
    echo -e "${RED}UNHEALTHY${NC}"
fi

# Worker health
echo -n "Worker: "
WORKER_LOG=$(docker compose -f docker-compose.production.yml logs worker --tail 1 2>/dev/null)
if echo "$WORKER_LOG" | grep -qi "error\|fatal\|panic"; then
    echo -e "${RED}ERROR${NC}"
elif [ -n "$WORKER_LOG" ]; then
    echo -e "${GREEN}RUNNING${NC}"
else
    echo -e "${YELLOW}UNKNOWN${NC}"
fi

# Database
echo -n "Database: "
if docker compose -f docker-compose.production.yml exec -T postgres pg_isready -U zovark -d zovark >/dev/null 2>&1; then
    echo -e "${GREEN}HEALTHY${NC}"
else
    echo -e "${RED}UNHEALTHY${NC}"
fi

# Redis
echo -n "Redis: "
REDIS_PW=$(grep REDIS_PASSWORD .env 2>/dev/null | cut -d= -f2 || echo "")
if docker compose -f docker-compose.production.yml exec -T redis redis-cli -a "$REDIS_PW" ping 2>/dev/null | grep -q "PONG"; then
    echo -e "${GREEN}HEALTHY${NC}"
else
    echo -e "${YELLOW}CHECK CONFIG${NC}"
fi

# LLM
echo -n "LLM: "
LLM_URL=$(grep ZOVARK_LLM_ENDPOINT .env 2>/dev/null | cut -d= -f2 || echo "http://host.docker.internal:11434/v1/chat/completions")
if curl -sf "${LLM_URL%/chat/completions}/models" >/dev/null 2>&1 || curl -sf "http://localhost:11434/v1/models" >/dev/null 2>&1; then
    echo -e "${GREEN}AVAILABLE${NC}"
else
    echo -e "${YELLOW}NOT DETECTED${NC} (LLM server not running — investigations will fail)"
fi

echo ""
