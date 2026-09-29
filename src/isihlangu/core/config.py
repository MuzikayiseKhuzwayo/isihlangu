"""Central configuration management for Isihlangu using Pydantic Settings."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment or .env file."""

    model_config = SettingsConfigDict(
        env_prefix="ISIHLANGU_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Datastore
    database_url: str = Field(default="sqlite+aiosqlite:///./data/isihlangu.db")

    # Scope & Guardrails
    allowed_cidrs: list[str] = Field(
        default_factory=lambda: [
            "127.0.0.1/32",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
    )
    allowed_domains: list[str] = Field(
        default_factory=lambda: [
            "localhost",
            "127.0.0.1",
            "api.internal",
            "canary.local",
        ]
    )

    # Canary / OOB Callback Server
    canary_host: str = "127.0.0.1"
    canary_port: int = 8877
    canary_public_url: str = "http://127.0.0.1:8877"

    # Local Inference Endpoint
    inference_endpoint: str = "http://127.0.0.1:11434/v1"
    inference_api_key: str = "local-key-not-required"
    strategist_model: str = "qwen2.5-coder:32b"
    operator_model: str = "qwen2.5-coder:7b"

    # Operational safety
    safe_mode: bool = True
    request_timeout_seconds: float = 15.0


# Global singleton instance
settings = Settings()
