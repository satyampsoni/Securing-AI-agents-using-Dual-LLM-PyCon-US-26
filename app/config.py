from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore",
    )

    app_title: str = "Dual-LLM Security Demo"
    environment: str = "development"
    app_base_url: str = Field(default="http://127.0.0.1:8000", alias="APP_BASE_URL")
    run_mode: str = Field(default="replay", alias="RUN_MODE")
    allow_sensitive_tools: bool = Field(default=False, alias="ALLOW_SENSITIVE_TOOLS")
    replay_dir: Path = Path("data/replays")
    mcp_connector_store_path: Path = Path("data/mcp_connectors.json")
    gmail_token_store_path: Path = Path("data/gmail_token.json")
    gmail_client_id: str | None = Field(default=None, alias="GMAIL_CLIENT_ID")
    gmail_client_secret: str | None = Field(default=None, alias="GMAIL_CLIENT_SECRET")
    gmail_redirect_uri: str | None = Field(default=None, alias="GMAIL_REDIRECT_URI")
    gmail_poll_query: str = Field(default="in:inbox", alias="GMAIL_POLL_QUERY")
    gmail_poll_max_results: int = Field(default=12, alias="GMAIL_POLL_MAX_RESULTS")

    quarantined_base_url: str | None = Field(default=None, alias="QUARANTINED_BASE_URL")
    quarantined_api_key: str | None = Field(default=None, alias="QUARANTINED_API_KEY")
    quarantined_model_name: str = Field(default="quarantine-replay-model", alias="QUARANTINED_MODEL_NAME")

    privileged_base_url: str | None = Field(default=None, alias="PRIVILEGED_BASE_URL")
    privileged_api_key: str | None = Field(default=None, alias="PRIVILEGED_API_KEY")
    privileged_model_name: str = Field(default="privileged-replay-model", alias="PRIVILEGED_MODEL_NAME")

    default_timeout_seconds: float = 20.0

    @property
    def use_live_models(self) -> bool:
        return self.run_mode.lower() == "live"

    @property
    def gmail_is_configured(self) -> bool:
        return bool(self.gmail_client_id and self.gmail_client_secret)

    @property
    def effective_gmail_redirect_uri(self) -> str:
        if self.gmail_redirect_uri:
            return self.gmail_redirect_uri
        return f"{self.app_base_url.rstrip('/')}/auth/gmail/callback"


@lru_cache
def get_settings() -> Settings:
    return Settings()
