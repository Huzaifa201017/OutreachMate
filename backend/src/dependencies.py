from typing import Annotated

from fastapi_mail import ConnectionConfig
from src.config import AppConfig
from fastapi import Depends, Request
from redis.asyncio.client import Redis


def get_redis(request: Request) -> Redis:
    return request.app.state.redis


def get_config() -> AppConfig:
    return AppConfig()


def get_system_mail_config(
    config: Annotated[AppConfig, Depends(get_config)],
) -> ConnectionConfig:
    """Get mail configuration singleton"""
    return ConnectionConfig(
        MAIL_USERNAME=config.MAIL_USERNAME,
        MAIL_PASSWORD=config.MAIL_PASSWORD,
        MAIL_FROM=config.MAIL_FROM,
        MAIL_FROM_NAME=config.MAIL_FROM_NAME,
        MAIL_SERVER=config.MAIL_SERVER,
        MAIL_PORT=config.MAIL_PORT,
        MAIL_STARTTLS=config.MAIL_STARTTLS,
        MAIL_SSL_TLS=config.MAIL_SSL_TLS,
        USE_CREDENTIALS=config.USE_CREDENTIALS,
        VALIDATE_CERTS=config.VALIDATE_CERTS,
        TEMPLATE_FOLDER=config.TEMPLATE_FOLDER,
        MAIL_DEBUG=config.MAIL_DEBUG,
    )
