from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', extra='ignore')

    app_name: str = 'AI-Security-Guard'
    app_version: str = '1.0.0'
    openai_api_key: str = Field(default='', alias='OPENAI_API_KEY')
    openai_model: str = 'gpt-4o-mini'
    max_input_length: int = 2000
    requests_per_minute: int = 30
    blocked_regex: str = r'(<script|DROP\s+TABLE|UNION\s+SELECT)'
    chat_history_file: str = 'data/chat_history.json'
    security_log_file: str = 'logs/security_events.jsonl'


settings = Settings()
