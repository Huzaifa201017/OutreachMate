from typing import Annotated

from fastapi import Depends
from redis.asyncio.client import Redis
from sqlalchemy.orm import Session

from src.database import get_db
from src.dependencies import get_redis, get_settings
from src.email.service import EmailService
from src.settings import Settings


def get_email_service(
    redis_client: Annotated[Redis, Depends(get_redis)],
    settings: Annotated[Settings, Depends(get_settings)],
    db: Annotated[Session, Depends(get_db)],
) -> EmailService:

    return EmailService(redis_client=redis_client, settings=settings, db=db)
