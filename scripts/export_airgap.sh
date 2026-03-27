#!/bin/bash
set -e

echo "=== ZOVARC Air-Gap Deployment Package Builder ==="
echo ""

DRY_RUN=false
if [[ "$1" == "--dry-run" ]]; then
  DRY_RUN=true
  echo "[DRY RUN MODE — no files will be created]"
  echo ""
fi

EXPORT_DIR="./zovarc-airgap-bundle"

run_or_print() {
  if $DRY_RUN; then
    echo "  [DRY RUN] $*"
  else
    eval "$@"
  fi
}

run_or_print "mkdir -p $EXPORT_DIR"

# 1. Save all Docker images
echo "[1/5] Saving Docker images..."
IMAGES=(
  "zovarc-mvp-api"
  "zovarc-mvp-worker"
  "zovarc-mvp-dashboard"
  "pgvector/pgvector:pg16"
  "temporalio/auto-setup:1.24.2"
  "redis:7-alpine"
  "ghcr.io/huggingface/text-embeddings-inference:cpu-1.2"
  "ollama/ollama:latest"
)

# Tag litellm image for export
run_or_print "docker tag docker.litellm.ai/berriai/litellm-database:main-stable zovarc-litellm:latest 2>/dev/null || true"
IMAGES+=("zovarc-litellm:latest")

for img in "${IMAGES[@]}"; do
  FILENAME=$(echo "$img" | tr '/:' '_').tar
  echo "  Saving $img → $FILENAME"
  run_or_print "docker save '$img' -o '$EXPORT_DIR/$FILENAME'"
done

# 2. Export Ollama model weights
echo ""
echo "[2/5] Exporting LLM model weights..."
run_or_print "docker cp zovarc-ollama:/root/.ollama '$EXPORT_DIR/ollama_models'"

# 3. Export embedding model weights
echo ""
echo "[3/5] Exporting embedding model weights..."
run_or_print "docker cp zovarc-embedding:/data '$EXPORT_DIR/embedding_model'"

# 4. Copy configuration files
echo ""
echo "[4/5] Copying configuration..."
run_or_print "cp docker-compose.yml '$EXPORT_DIR/'"
run_or_print "cp docker-compose.airgap.yml '$EXPORT_DIR/'"
run_or_print "cp litellm_config.yaml '$EXPORT_DIR/'"
run_or_print "cp init.sql '$EXPORT_DIR/'"
run_or_print "cp scripts/seed_skills.py '$EXPORT_DIR/'"
run_or_print "cp -r worker/ '$EXPORT_DIR/worker_src/'"

# Create air-gap .env
echo "  Creating .env for air-gap..."
if ! $DRY_RUN; then
cat > "$EXPORT_DIR/.env" << 'EOF'
ZOVARC_LLM_MODEL=zovarc-local
JWT_SECRET=change-me-in-production
DATABASE_URL=postgresql://zovarc:zovarc@postgres:5432/zovarc
LITELLM_MASTER_KEY=sk-zovarc-local
OPENROUTER_API_KEY=not-needed-airgap
EOF
fi

# 5. Create install script
echo ""
echo "[5/5] Creating install script..."
if ! $DRY_RUN; then
cat > "$EXPORT_DIR/install.sh" << 'INSTALLER'
#!/bin/bash
set -e
echo "=== ZOVARC Air-Gap Installation ==="
echo "Loading Docker images (this may take several minutes)..."

for tarfile in *.tar; do
  echo "  Loading $tarfile..."
  docker load -i "$tarfile"
done

echo "Restoring LLM model weights..."
mkdir -p ollama_volume
cp -r ollama_models/* ollama_volume/

echo "Restoring embedding model weights..."
mkdir -p embedding_volume
cp -r embedding_model/* embedding_volume/

echo "Starting ZOVARC platform..."
docker compose -f docker-compose.airgap.yml up -d

echo "Waiting for services to start (60 seconds)..."
sleep 60

echo "Seeding threat intelligence skills..."
docker exec $(docker ps --filter "name=worker" --format "{{.Names}}" | head -1) python /app/scripts/seed_skills.py

echo ""
echo "=== ZOVARC Installation Complete ==="
echo "Dashboard: http://localhost:3000"
echo "API: http://localhost:8090"
echo ""
echo "Default credentials:"
echo "  Admin: admin@zovarc.local / admin123"
echo "  Analyst: analyst@zovarc.local / analyst123"
echo ""
echo "To verify: docker compose -f docker-compose.airgap.yml ps"
INSTALLER

chmod +x "$EXPORT_DIR/install.sh"
fi

# Calculate bundle size
echo ""
echo "=== Bundle Complete ==="
echo "Location: $EXPORT_DIR/"
if ! $DRY_RUN; then
  du -sh "$EXPORT_DIR/"
fi
echo ""
echo "Transfer this directory to the air-gapped network."
echo "On the target machine, run: cd zovarc-airgap-bundle && ./install.sh"
