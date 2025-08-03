from redis.asyncio import Redis
from sqlalchemy.orm import Session

from src.email.providers.base import BaseEmailProvider
from src.email.providers.gmail import GmailProvider
from src.settings import Settings


class ProviderFactory:

    @staticmethod
    def get_provider(
        provider_name: str, redis_client: Redis, settings: Settings, db: Session
    ) -> BaseEmailProvider:
        if provider_name.lower() == "gmail":
            return GmailProvider(redis_client=redis_client, settings=settings, db=db)
        else:
            raise ValueError(f"Unsupported provider: {provider_name}")
