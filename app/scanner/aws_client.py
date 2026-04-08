from __future__ import annotations

import boto3
from botocore.config import Config

from app.utils.config import get_settings


def build_session() -> boto3.Session:
    settings = get_settings()
    if settings.aws_profile:
        return boto3.Session(profile_name=settings.aws_profile, region_name=settings.aws_region)
    return boto3.Session(region_name=settings.aws_region)


def build_client(service_name: str):
    session = build_session()
    return session.client(service_name, config=Config(retries={"max_attempts": 3}))
