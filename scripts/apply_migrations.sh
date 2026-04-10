#!/usr/bin/env bash
# Apply PostgreSQL migrations from migrations/*.sql in sorted filename order.
# Ticket 6: complements "docker compose exec <api-service> ./hydra-api migrate up"
# (API migrate records schema_migrations; this script supports psql-only / CI-style apply).
#
# ── Two-phase apply (Ticket 2 / SurrealDB cutover) ─────────────────────────
#   Phase 1 (safe default): migrations through 067, then 069 — 068 is SKIPPED.
#     068_ticket2_surreal_graph_pgvector_retirement.sql drops PostgreSQL entity
#     graph / pgvector paths and MUST run only after SurrealDB is live and the
#     entity write path is migrated.
#   Phase 2 (explicit opt-in): after cutover, re-run with --include-068 (psql mode
#     prompts for confirmation; type APPLY-068).
#
# Usage:
#   ./scripts/apply_migrations.sh [--from 040] [--to 069] [--include-068] [psql|api]
#
# Modes:
#   psql (default) — docker compose exec -T postgres psql ... < each file
#                    (068 excluded unless --include-068 + confirmation)
#   api            — docker compose exec -T api ./hydra-api migrate up
#                    WARNING: applies every pending migration file, including 068
#                    if it is pending. Prefer psql mode for two-phase sequencing.
#
# Env:
#   API_SERVICE         Compose service name for api mode (default: api)
#   POSTGRES_SERVICE    default: postgres
#   POSTGRES_USER       default: zovark
#   POSTGRES_DB         default: zovark
#   PGPASSWORD          optional; forwarded into the postgres container for psql
#   COMPOSE_FILE        optional (same as docker compose -f)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FROM="001"
TO="999"
MODE="psql"
INCLUDE_068=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from)
      FROM="${2:?}"
      shift 2
      ;;
    --to)
      TO="${2:?}"
      shift 2
      ;;
    --include-068)
      INCLUDE_068=1
      shift
      ;;
    psql|api)
      MODE="$1"
      shift
      ;;
    -h|--help)
      sed -n '1,45p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

API_SERVICE="${API_SERVICE:-api}"

if [[ "$MODE" == "api" ]]; then
  exec docker compose exec -T "$API_SERVICE" ./hydra-api migrate up
fi

if (( 10#$FROM == 68 && 10#$TO == 68 )) && [[ "$INCLUDE_068" != "1" ]]; then
  echo "Error: range is only 068; add --include-068 after SurrealDB + entity write cutover." >&2
  exit 1
fi

POSTGRES_SERVICE="${POSTGRES_SERVICE:-postgres}"
POSTGRES_USER="${POSTGRES_USER:-zovark}"
POSTGRES_DB="${POSTGRES_DB:-zovark}"

exec_args=(-T)
if [[ -n "${PGPASSWORD:-}" ]]; then
  exec_args+=(-e "PGPASSWORD=${PGPASSWORD}")
fi

shopt -s nullglob
all_files=("$ROOT/migrations/"*.sql)

if [[ ${#all_files[@]} -eq 0 ]]; then
  echo "No migrations found under $ROOT/migrations/" >&2
  exit 1
fi

if (( 10#$FROM <= 68 && 10#$TO >= 68 )) && [[ "$INCLUDE_068" != "1" ]]; then
  echo "Note: migration 068 is excluded by default (SurrealDB cutover). Use --include-068 after entity graph is on SurrealDB." >&2
fi

while IFS= read -r f; do
  [[ -z "$f" || ! -f "$f" ]] && continue
  base="$(basename "$f")"
  num="${base:0:3}"
  if ! [[ "$num" =~ ^[0-9]{3}$ ]]; then
    echo "Skip (unrecognized prefix): $base" >&2
    continue
  fi
  if (( 10#$num < 10#$FROM || 10#$num > 10#$TO )); then
    continue
  fi

  if (( 10#$num == 68 )); then
    if [[ "$INCLUDE_068" != "1" ]]; then
      echo "Skipping $base (Ticket 2: apply only after SurrealDB + entity write path; use --include-068)." >&2
      continue
    fi
    if [[ -z "${ZOVARK_068_CONFIRMED:-}" ]]; then
      echo "" >&2
      echo "You are about to apply $base — PostgreSQL entity graph / pgvector retirement." >&2
      echo "Confirm SurrealDB is live and entity writes are migrated. Type APPLY-068 to continue:" >&2
      read -r _confirm
      if [[ "$_confirm" != "APPLY-068" ]]; then
        echo "Aborted (expected APPLY-068)." >&2
        exit 1
      fi
      export ZOVARK_068_CONFIRMED=1
    fi
  fi

  echo "Applying $base ..."
  docker compose exec "${exec_args[@]}" "$POSTGRES_SERVICE" \
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -f - < "$f"
done < <(printf '%s\n' "${all_files[@]}" | sort)

echo "Done (range ${FROM}-${TO}, psql mode)."
