#!/bin/bash
# ZOVARK 48-Hour PoV Deployment
# Run on customer's Linux server with Docker installed.
#
# Usage: bash scripts/pov/deploy.sh

set -e

echo "╔══════════════════════════════════════╗"
echo "║  ZOVARK PoV Deployment                ║"
echo "║  Estimated time: 10 minutes          ║"
echo "╚══════════════════════════════════════╝"
echo ""

# 1. Check prerequisites
echo "=== Checking prerequisites ==="
command -v docker >/dev/null 2>&1 || { echo "ERROR: Docker is required but not installed."; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "ERROR: Docker Compose V2 is required."; exit 1; }
echo "  ✓ Docker and Docker Compose V2 found"

# 2. Generate secrets
echo ""
echo "=== Generating secrets ==="
JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))")
REDIS_PASSWORD=$(openssl rand -hex 16 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(16))")
NATS_PASSWORD=$(openssl rand -hex 16 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(16))")
ENCRYPTION_KEY=$(openssl rand -hex 16 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(16))")
BACKUP_PASSPHRASE=$(openssl rand -hex 16 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(16))")
echo "  ✓ Cryptographic secrets generated"

# 3. Create .env from template
echo ""
echo "=== Configuring environment ==="
if [ ! -f .env.example ]; then
    echo "ERROR: .env.example not found. Are you in the zovark-mvp directory?"
    exit 1
fi

cp .env.example .env
sed -i "s|^JWT_SECRET=.*|JWT_SECRET=$JWT_SECRET|" .env
sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=zovark_pov_2026|" .env
sed -i "s|^ZOVARK_LLM_KEY=.*|ZOVARK_LLM_KEY=sk-zovark-pov-$(openssl rand -hex 8 2>/dev/null || echo 'dev-key')|" .env
sed -i "s|^MINIO_ROOT_USER=.*|MINIO_ROOT_USER=zovark-pov|" .env
sed -i "s|^MINIO_ROOT_PASSWORD=.*|MINIO_ROOT_PASSWORD=$(openssl rand -hex 12 2>/dev/null || echo 'minio-pov-2026')|" .env

# Add security vars if not present
grep -q "REDIS_PASSWORD" .env || echo "REDIS_PASSWORD=$REDIS_PASSWORD" >> .env
grep -q "NATS_PASSWORD" .env || echo "NATS_PASSWORD=$NATS_PASSWORD" >> .env
grep -q "ZOVARK_ENCRYPTION_KEY" .env || echo "ZOVARK_ENCRYPTION_KEY=$ENCRYPTION_KEY" >> .env
grep -q "BACKUP_PASSPHRASE" .env || echo "BACKUP_PASSPHRASE=$BACKUP_PASSPHRASE" >> .env
echo "  ✓ .env configured with generated secrets"

# 4. Check for GPU (optional)
echo ""
echo "=== Checking GPU ==="
if command -v nvidia-smi >/dev/null 2>&1; then
    echo "  ✓ NVIDIA GPU detected"
    echo "  To use local vLLM inference: docker compose --profile vllm up -d"
    echo "  For this PoV, using cloud LLM providers (faster setup)"
else
    echo "  No GPU detected — using cloud LLM providers"
fi

# 5. Start stack
echo ""
echo "=== Starting ZOVARK stack ==="
docker compose up -d 2>&1 | tail -5
echo "  ✓ Services starting..."

# 6. Wait for health
echo ""
echo "=== Waiting for services ==="
for i in $(seq 1 60); do
    if curl -sf http://localhost:8090/health | grep -q '"status"' 2>/dev/null; then
        echo "  ✓ ZOVARK API is healthy!"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo "  WARNING: Health check timed out. Check 'docker compose logs api'"
    fi
    printf "  Waiting... (%d/60)\r" "$i"
    sleep 2
done

# 7. Run migrations
echo ""
echo "=== Applying database migrations ==="
docker compose exec -T zovark-api ./zovark-api migrate up 2>&1 || echo "  (migrations may already be applied)"
echo "  ✓ Database ready"

# 8. Create PoV admin user
echo ""
echo "=== Creating PoV admin user ==="
curl -sf -X POST http://localhost:8090/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"pov-admin","email":"admin@pov.local","password":"PoV-2026-Zovark!"}' 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "  (user may already exist)"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  ZOVARK is running!                               ║"
echo "║                                                  ║"
echo "║  Dashboard: http://localhost:3000                 ║"
echo "║  API:       http://localhost:8090/health          ║"
echo "║  Grafana:   http://localhost:3001                 ║"
echo "║                                                  ║"
echo "║  Login:     pov-admin / PoV-2026-Zovark!          ║"
echo "║                                                  ║"
echo "║  Next: Import alerts with:                       ║"
echo "║  python scripts/pov/import_alerts.py \\           ║"
echo "║    --format splunk --file your_alerts.csv \\      ║"
echo "║    --tenant-id <your-tenant-id>                  ║"
echo "╚══════════════════════════════════════════════════╝"
