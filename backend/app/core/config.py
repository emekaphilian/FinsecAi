from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


# The API can be started either from ``backend/`` or from the repository root.
# Use absolute paths so both launch modes load the same project configuration.
BACKEND_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_ROOT.parent
PRODUCTION_FRONTEND_ORIGIN = "https://finsec-ai.vercel.app"


class Settings(BaseSettings):
    # The root .env is the canonical local configuration.  Keep backend/.env
    # supported for existing deployments, while allowing root values to win.
    model_config = SettingsConfigDict(
        env_file=(BACKEND_ROOT / ".env", PROJECT_ROOT / ".env"),
        protected_namespaces=(),
        extra="ignore",
    )

    database_url: str = "postgresql+psycopg2://finsecai:finsecai@localhost:5432/finsecai"
    redis_url: str = "redis://localhost:6379/0"

    jwt_secret: str = "dev-secret-change-me"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    jwt_refresh_expire_days: int = 14

    # Nigerian AML compliance defaults. Treat these as regulatory floors and
    # confirm current CBN/NFIU guidance before a production submission.
    audit_retention_years: int = 5
    str_reporting_sla_hours: int = 24
    str_risk_threshold: float = 0.85
    environment: str = "development"

    # Comma-separated list of allowed frontend origins.
    # Environment-specific origins can be added in .env; the canonical
    # production frontend remains allowed even when that setting is overridden.
    cors_origins: str = (
        "http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3001,"
        f"{PRODUCTION_FRONTEND_ORIGIN}"
    )

    llm_provider: str = "cohere"
    llm_fallback_provider: str = "local"
    local_llm_url: str = "http://localhost:11434/api/generate"
    local_llm_model: str = "llama3.2"
    local_llm_timeout_seconds: int = 120
    embedding_provider: str = "cohere"
    cohere_api_key: str = ""
    cohere_chat_model: str = "command-a-plus-05-2026"
    cohere_embed_model: str = "embed-v4.0"
    cohere_embed_dimension: int = 1536
    cohere_similarity_threshold: float = 0.40
    cohere_temperature: float = 0.1
    cohere_timeout_seconds: int = 60

    openai_api_key: str = ""
    openai_embed_model: str = "text-embedding-3-small"
    openai_embed_dimension: int = 1536

    # Organizational policy values, not regulatory thresholds.
    model_min_precision: float = 0.80
    model_min_recall: float = 0.70
    model_min_f1: float = 0.75
    model_min_pr_auc: float = 0.60
    model_min_label_count: int = 500
    model_min_fraud_label_count: int = 50
    seed_demo_data: bool = True
    owner_email: str = "owner@finsecai.com"
    owner_password: str = "123"

    @property
    def cors_origin_list(self) -> list[str]:
        origins = [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
        if PRODUCTION_FRONTEND_ORIGIN not in origins:
            origins.append(PRODUCTION_FRONTEND_ORIGIN)
        return origins

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() == "production"


settings = Settings()
