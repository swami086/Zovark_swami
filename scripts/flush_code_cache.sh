#!/bin/bash
set -e
REDIS_PASS="${REDIS_PASSWORD:-hydra-redis-dev-2026}"
echo "Flushing Zovark code cache..."
COUNT=$(docker compose exec -T redis redis-cli -a "$REDIS_PASS" --no-auth-warning \
  EVAL "local keys = redis.call('keys', 'zovark:code_cache:*'); for _,k in ipairs(keys) do redis.call('del', k) end; return #keys" 0 2>/dev/null)
echo "Flushed ${COUNT:-0} cached entries."
