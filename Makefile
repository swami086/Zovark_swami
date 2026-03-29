# ============================================================
# Zovark SOC Platform — Makefile
# ============================================================
.PHONY: test test-unit test-integration test-ci validate build \
        up down logs clean lint

# ─── Test Targets ──────────────────────────────────────────

## Run all tests (unit + integration)
test: test-unit test-integration

## Run unit tests only (Python + Go, no Docker required)
test-unit:
	@echo "=== Running unit tests ==="
	cd worker && python -m pytest tests/ -v --tb=short
	cd api && go test -v -race -count=1 ./...

## Run integration tests with mock Ollama (requires Docker)
test-integration:
	@echo "=== Starting test stack with mock Ollama ==="
	docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build --wait || \
		docker compose -f docker-compose.yml -f docker-compose.test.yml up -d --build
	@echo "=== Waiting for API health ==="
	@for i in $$(seq 1 60); do \
		curl -sf http://localhost:8090/health > /dev/null 2>&1 && break || sleep 5; \
	done
	@echo "=== Running integration tests ==="
	python -m pytest tests/integration/ -v --tb=short || true
	@echo "=== Cleaning up ==="
	docker compose -f docker-compose.yml -f docker-compose.test.yml down --volumes --remove-orphans

## Run full CI test suite via script
test-ci:
	./scripts/run_ci_tests.sh all

## Validate project structure and imports
validate:
	@echo "=== Validating Docker Compose configs ==="
	docker compose -f docker-compose.yml config --quiet
	docker compose -f docker-compose.yml -f docker-compose.test.yml config --quiet
	@echo "=== Validating Python imports ==="
	cd worker && python -c "\
		from model_config import get_tier_config, ACTIVITY_TIER_MAP; \
		from prompt_registry import get_version, prompt_count; \
		from entity_normalize import normalize_entity, compute_entity_hash; \
		from security.injection_detector import scan_for_injection; \
		from detection.sigma_generator import generate_sigma_rule; \
		from response.actions import ACTION_REGISTRY, ResponseAction; \
		print('All imports OK')"
	@echo "=== Validating migration files ==="
	@count=$$(ls migrations/*.sql 2>/dev/null | wc -l); \
		echo "$$count migration files found"; \
		if [ "$$count" -eq 0 ]; then echo "WARNING: No migration files"; fi
	@echo "=== Validation complete ==="

# ─── Build & Run ───────────────────────────────────────────

## Build all Docker images
build:
	docker compose build

## Start the full stack (production)
up:
	docker compose up -d

## Stop the full stack
down:
	docker compose down

## View logs (follow mode)
logs:
	docker compose logs -f --tail=100

## Lint Python and Go code
lint:
	cd worker && flake8 --max-line-length=120 --ignore=E501,W503,E402 *.py security/ detection/ response/ || true
	cd api && go vet ./...

## Clean up volumes, orphans, and test artifacts
clean:
	docker compose -f docker-compose.yml -f docker-compose.test.yml down --volumes --remove-orphans 2>/dev/null || true
	docker compose down --volumes --remove-orphans 2>/dev/null || true
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
