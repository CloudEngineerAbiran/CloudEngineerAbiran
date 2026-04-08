from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Cloud Vulnerability Scanner"
    app_env: str = Field(default="dev")
    log_level: str = Field(default="INFO")

    aws_region: str = Field(default="us-east-1")
    aws_profile: str | None = None

    database_url: str = Field(default="sqlite:///./scanner.db")
    reports_dir: str = Field(default="./reports")
    config_file: str | None = Field(default=None)

    scan_s3_enabled: bool = True
    scan_iam_enabled: bool = True
    scan_ec2_enabled: bool = True

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    def load_file_overrides(self) -> "Settings":
        if not self.config_file:
            return self

        config_path = Path(self.config_file)
        if not config_path.exists():
            return self

        with config_path.open("r", encoding="utf-8") as handle:
            payload: dict[str, Any] = yaml.safe_load(handle) or {}

        merged = self.model_dump()
        merged.update(payload)
        return Settings(**merged)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings().load_file_overrides()
