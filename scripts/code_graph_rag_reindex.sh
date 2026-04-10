#!/usr/bin/env bash
# Full Memgraph reindex for Code Graph RAG (vitali87/code-graph-rag).
# Uses --clean because MCP delete_project() leaves Module/ExternalPackage orphans;
# dedicated Zovark Memgraph (docker-compose.code-graph-rag.yml) should always wipe on full rebuild.
#
# Requires code-graph-rag deps with tree-sitter grammars (Go, TS, …): run once in CGR_HOME:
#   uv sync
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CGR_HOME="${CGR_HOME:-$HOME/Documents/code-graph-rag}"
export TARGET_REPO_PATH="$ROOT"
export MEMGRAPH_HOST="${MEMGRAPH_HOST:-127.0.0.1}"
export MEMGRAPH_PORT="${MEMGRAPH_PORT:-7688}"
cd "$CGR_HOME"
uv sync >/dev/null
exec uv run code-graph-rag start --update-graph --clean --no-confirm "$@"
