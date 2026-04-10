"""Pytest hooks — host runs should not spam OTLP to Docker-only hostnames."""
import os

# In containers, compose sets OTEL_ENABLED=true; do not override.
if not os.path.exists("/.dockerenv"):
    os.environ.setdefault("OTEL_ENABLED", "false")


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "integration: docker-network / optional external services"
    )
