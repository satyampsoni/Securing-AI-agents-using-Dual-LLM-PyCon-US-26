from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from dual_llm_security.models import RunBackend


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore",
    )

    run_mode: RunBackend = Field(default=RunBackend.REPLAY, alias="RUN_MODE")
    allow_sensitive_tools: bool = Field(default=False, alias="ALLOW_SENSITIVE_TOOLS")
    datasets_dir: Path = Field(default=Path("datasets"), alias="DATASETS_DIR")
    default_timeout_seconds: float = Field(default=30.0, alias="DEFAULT_TIMEOUT_SECONDS")

    quarantined_base_url: str | None = Field(default=None, alias="QUARANTINED_BASE_URL")
    quarantined_api_key: str | None = Field(default=None, alias="QUARANTINED_API_KEY")
    quarantined_model_name: str = Field(default="quarantine-replay-model", alias="QUARANTINED_MODEL_NAME")

    privileged_base_url: str | None = Field(default=None, alias="PRIVILEGED_BASE_URL")
    privileged_api_key: str | None = Field(default=None, alias="PRIVILEGED_API_KEY")
    privileged_model_name: str = Field(default="privileged-replay-model", alias="PRIVILEGED_MODEL_NAME")

    @property
    def use_live_models(self) -> bool:
        return self.run_mode == RunBackend.LIVE


@lru_cache
def get_settings() -> Settings:
    return Settings()
