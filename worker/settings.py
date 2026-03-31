"""
Centralized configuration for Zovark worker.
Reads from environment variables with ZOVARK_ prefix, falls back to .env file.
SecretStr prevents accidental logging of credentials.
"""
import os
from pydantic_settings import BaseSettings
from pydantic import SecretStr


class ZovarkSettings(BaseSettings):
    # Database
    db_host: str = "pgbouncer"
    db_port: int = 5432
    db_user: str = "zovark"
    db_password: SecretStr = SecretStr("hydra_dev_2026")
    db_name: str = "zovark"

    # Redis
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_password: SecretStr = SecretStr("hydra-redis-dev-2026")

    # LLM (Ollama)
    llm_base_url: str = "http://host.docker.internal:11434"
    llm_endpoint: str = "http://host.docker.internal:11434/v1/chat/completions"
    llm_fast_model: str = "llama3.2:3b"
    llm_quality_model: str = "llama3.1:8b"
    llm_key: str = "sk-zovark-dev-2026"

    # Execution
    execution_mode: str = "tools"
    path_d_fallback_enabled: bool = True
    mode: str = "full"  # "full" or "templates-only"

    # Governance
    default_autonomy_level: str = "observe"

    # Operational
    max_investigation_timeout_seconds: int = 300
    max_concurrent_activities: int = 8

    # Observability
    otel_enabled: bool = True
    otel_endpoint: str = "http://zovark-signoz-collector:4318"

    model_config = {
        "env_prefix": "ZOVARK_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }

    @property
    def database_url(self) -> str:
        return f"postgresql://{self.db_user}:{self.db_password.get_secret_value()}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def redis_url(self) -> str:
        return f"redis://:{self.redis_password.get_secret_value()}@{self.redis_host}:{self.redis_port}/0"


# Singleton — import this everywhere
try:
    settings = ZovarkSettings()
except Exception:
    # Fallback for test environments without .env
    settings = ZovarkSettings(
        db_password=SecretStr("hydra_dev_2026"),
        redis_password=SecretStr("hydra-redis-dev-2026"),
    )
