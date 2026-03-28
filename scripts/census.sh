#!/bin/bash
# scripts/census.sh — regeneratable codebase census
set -e

OUTPUT="docs/CODEBASE_CENSUS.md"
# Directories to always exclude from counts
EXCLUDE="-not -path */.claude/* -not -path */node_modules/* -not -path */__pycache__/* -not -path */.venv/* -not -path */.git/*"

_find() {
  find . "$@" -not -path "*/.claude/*" -not -path "*/node_modules/*" -not -path "*/__pycache__/*" -not -path "*/.venv/*" -not -path "*/.git/*" 2>/dev/null
}

echo "# ZOVARK Codebase Census" > "$OUTPUT"
echo "" >> "$OUTPUT"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT"
echo "Commit: $(git rev-parse --short HEAD)" >> "$OUTPUT"
echo "" >> "$OUTPUT"

echo "## Lines of Code" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "| Language | Source | Tests | Total |" >> "$OUTPUT"
echo "|----------|--------|-------|-------|" >> "$OUTPUT"

# Go
GO_SRC=$(_find -name "*.go" -not -name "*_test.go" -not -path "*/vendor/*" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
GO_TEST=$(_find -name "*_test.go" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
GO_SRC=${GO_SRC:-0}
GO_TEST=${GO_TEST:-0}
echo "| Go | $GO_SRC | $GO_TEST | $((GO_SRC + GO_TEST)) |" >> "$OUTPUT"

# Python
PY_SRC=$(_find -name "*.py" -not -name "test_*" -not -name "*_test.py" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
PY_TEST=$(_find -name "test_*.py" -o -name "*_test.py" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
PY_SRC=${PY_SRC:-0}
PY_TEST=${PY_TEST:-0}
echo "| Python | $PY_SRC | $PY_TEST | $((PY_SRC + PY_TEST)) |" >> "$OUTPUT"

# TypeScript/React
TS_SRC=$(_find \( -name "*.ts" -o -name "*.tsx" \) -not -name "*.test.*" -not -name "*.spec.*" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
TS_TEST=$(_find \( -name "*.test.ts" -o -name "*.test.tsx" -o -name "*.spec.ts" \) | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
TS_SRC=${TS_SRC:-0}
TS_TEST=${TS_TEST:-0}
echo "| TypeScript | $TS_SRC | $TS_TEST | $((TS_SRC + TS_TEST)) |" >> "$OUTPUT"

# SQL
SQL_LOC=$(_find -name "*.sql" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
SQL_LOC=${SQL_LOC:-0}
echo "| SQL | $SQL_LOC | — | $SQL_LOC |" >> "$OUTPUT"

# Shell
SH_LOC=$(_find -name "*.sh" | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
SH_LOC=${SH_LOC:-0}
echo "| Shell | $SH_LOC | — | $SH_LOC |" >> "$OUTPUT"

# YAML
YAML_LOC=$(_find \( -name "*.yaml" -o -name "*.yml" \) | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
YAML_LOC=${YAML_LOC:-0}
echo "| YAML/Config | $YAML_LOC | — | $YAML_LOC |" >> "$OUTPUT"

TOTAL=$((GO_SRC + GO_TEST + PY_SRC + PY_TEST + TS_SRC + TS_TEST + SQL_LOC + SH_LOC + YAML_LOC))
echo "| **Total** | — | — | **$TOTAL** |" >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "## File Counts by Directory" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "| Directory | Files | Description |" >> "$OUTPUT"
echo "|-----------|-------|-------------|" >> "$OUTPUT"

declare -A DESCRIPTIONS
DESCRIPTIONS[api]="Go API gateway — auth, RBAC, handlers, middleware"
DESCRIPTIONS[worker]="Python Temporal worker — investigation pipeline"
DESCRIPTIONS[dashboard]="React 19 + Vite 7 + Tailwind 4 frontend"
DESCRIPTIONS[mcp-server]="TypeScript MCP server (tools, resources, prompts)"
DESCRIPTIONS[sandbox]="AST prefilter + seccomp + kill timer"
DESCRIPTIONS[scripts]="Operational scripts (PoV, load testing, census)"
DESCRIPTIONS[migrations]="SQL migration files (001-039)"
DESCRIPTIONS[k8s]="Kubernetes manifests (Kustomize, 4 overlays)"
DESCRIPTIONS[helm]="Helm charts for K8s deployment"
DESCRIPTIONS[terraform]="AWS/GCP infrastructure-as-code"
DESCRIPTIONS[config]="PostgreSQL configuration"
DESCRIPTIONS[proxy]="Squid egress proxy configuration"
DESCRIPTIONS[monitoring]="Prometheus rules + Grafana dashboards"
DESCRIPTIONS[security-fixes]="Security remediation specs and reports"
DESCRIPTIONS[sdk]="Client SDK"
DESCRIPTIONS[tests]="Integration tests + test corpus"
DESCRIPTIONS[docs]="Architecture, deployment, security docs"
DESCRIPTIONS[demo]="Demo scenario data"
DESCRIPTIONS[files]="Prompt archives"
DESCRIPTIONS[data]="Runtime data directory"
DESCRIPTIONS[temporal-config]="Temporal workflow engine configuration"
DESCRIPTIONS[.github]="CI/CD workflows"

for dir in api worker dashboard mcp-server sandbox scripts migrations k8s helm terraform config proxy monitoring security-fixes sdk tests docs demo files data temporal-config .github; do
  if [ -d "$dir" ]; then
    count=$(find "$dir" -type f -not -path "*/node_modules/*" -not -path "*/__pycache__/*" -not -path "*/.venv/*" -not -name "*.pyc" 2>/dev/null | wc -l)
    desc="${DESCRIPTIONS[$dir]:-}"
    echo "| $dir/ | $count | $desc |" >> "$OUTPUT"
  fi
done

echo "" >> "$OUTPUT"
echo "## Go Source Files" >> "$OUTPUT"
echo "" >> "$OUTPUT"
_find -name "*.go" -not -name "*_test.go" -not -path "*/vendor/*" | sort | while read f; do
  lines=$(wc -l < "$f")
  echo "- \`$f\` ($lines lines)" >> "$OUTPUT"
done

echo "" >> "$OUTPUT"
echo "## Python Source Files (worker/)" >> "$OUTPUT"
echo "" >> "$OUTPUT"
find ./worker -name "*.py" -not -path "*/__pycache__/*" 2>/dev/null | sort | while read f; do
  lines=$(wc -l < "$f")
  echo "- \`$f\` ($lines lines)" >> "$OUTPUT"
done

echo "" >> "$OUTPUT"
echo "## Database" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "- Migration files: $(ls migrations/*.sql 2>/dev/null | wc -l)" >> "$OUTPUT"
echo "- Init schema: init.sql" >> "$OUTPUT"

echo "Census complete: $OUTPUT"
