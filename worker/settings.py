"""
Centralized configuration for Zovark worker.
Reads from environment variables with ZOVARK_ prefix, falls back to .env file.
SecretStr prevents accidental logging of credentials.
"""
import os
from pydantic import Field, AliasChoices, SecretStr
from pydantic_settings import BaseSettings


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

    # OpenAI / LLM — Ticket 8 defaults: OpenAI Chat Completions + gpt-4o-mini
    # ZOVARK_LLM_PROVIDER: "openai" or "local" (llama.cpp / Ollama-compatible)
    llm_provider: str = "openai"
    llm_base_url: str = "https://api.openai.com"
    llm_endpoint: str = "https://api.openai.com/v1/chat/completions"
    llm_fast_model: str = "gpt-4o-mini"
    llm_quality_model: str = "gpt-4o-mini"
    # Legacy bearer (local inference); OpenAI auth uses openai_api_key first
    llm_key: str = ""
    openai_api_key: SecretStr = Field(
        default_factory=lambda: SecretStr(""),
        validation_alias=AliasChoices("OPENAI_API_KEY", "ZOVARK_OPENAI_API_KEY"),
    )

    # Execution
    execution_mode: str = "tools"
    path_d_fallback_enabled: bool = True
    mode: str = "full"  # "full" or "templates-only"

    # Governance
    default_autonomy_level: str = "observe"

    # External threat intel (attack-surface API). Default off for air-gap / silent-failure avoidance.
    threat_intel_enabled: bool = False

    # LLM context budgeting (approximate; chars/4 heuristic in llm_client)
    context_token_budget: int = 12000

    # Optional absolute path to a GBNF grammar file (overrides grammar_name -> worker/grammars/*.gbnf)
    grammar_file: str = ""

    # DPO forge — override NVIDIA default; set to local llama-server chat completions URL for air-gap
    dpo_forge_endpoint: str = ""

    # Operational
    max_investigation_timeout_seconds: int = 300
    max_concurrent_activities: int = 8

    # Parallel tool execution (Feature C)
    parallel_tools_enabled: bool = False  # ZOVARK_PARALLEL_TOOLS_ENABLED
    max_parallel_tools: int = 4  # ZOVARK_MAX_PARALLEL_TOOLS (1-8)

    # Observability — docker-compose sets OTEL_ENABLED + OTEL_EXPORTER_OTLP_ENDPOINT (no ZOVARK_ prefix).
    # Aliases keep worker aligned with standard OTEL env vars and compose.
    otel_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("OTEL_ENABLED", "ZOVARK_OTEL_ENABLED"),
    )
    otel_endpoint: str = Field(
        default="http://zovark-signoz-collector:4318",
        validation_alias=AliasChoices(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "ZOVARK_OTEL_ENDPOINT",
        ),
    )

    # Optional data plane (SurrealDB + Redpanda + DuckDB) — docker-compose.data-plane.yml
    redpanda_enabled: bool = False
    redpanda_brokers: str = "redpanda:9092"
    redpanda_topic_investigations: str = "zovark.investigations.completed"
    surreal_enabled: bool = False
    surreal_http_url: str = "http://surrealdb:8000"
    surreal_user: str = "root"
    surreal_password: SecretStr = SecretStr("change-me-surreal")
    surreal_ns: str = "zovark"
    surreal_db: str = "core"
    duckdb_enabled: bool = False
    duckdb_path: str = "/data/duckdb/analytics.duckdb"

    model_config = {
        "env_prefix": "ZOVARK_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
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
        openai_api_key=SecretStr(""),
    )
