from typing import Annotated

from fastapi import Depends, Request
from fastapi_mail import ConnectionConfig
from redis.asyncio.client import Redis

from src.settings import Settings


def get_redis(request: Request) -> Redis:
    return request.app.state.redis


def get_settings() -> Settings:
    return Settings()  # type: ignore


def get_system_mail_config(
    settings: Annotated[Settings, Depends(get_settings)],
) -> ConnectionConfig:
    """Get mail configuration singleton"""

    return ConnectionConfig(
        MAIL_USERNAME=settings.MAIL_USERNAME,
        MAIL_PASSWORD=settings.MAIL_PASSWORD,
        MAIL_FROM=settings.MAIL_FROM,
        MAIL_FROM_NAME=settings.MAIL_FROM_NAME,
        MAIL_SERVER=settings.MAIL_SERVER,
        MAIL_PORT=settings.MAIL_PORT,
        MAIL_STARTTLS=settings.MAIL_STARTTLS,
        MAIL_SSL_TLS=settings.MAIL_SSL_TLS,
        USE_CREDENTIALS=settings.USE_CREDENTIALS,
        VALIDATE_CERTS=settings.VALIDATE_CERTS,
        TEMPLATE_FOLDER=settings.TEMPLATE_FOLDER,
        MAIL_DEBUG=settings.MAIL_DEBUG,
    )
