from fastapi import Request
from redis.asyncio import Redis
from sqlalchemy.orm import Session

from src.email.providers.provider_factory import ProviderFactory
from src.models import UserEmailAccount
from src.settings import Settings


class EmailService:

    def __init__(self, redis_client: Redis, settings: Settings, db: Session):
        self.provider_factory = ProviderFactory()
        self.redis_client = redis_client
        self.settings = settings
        self.db = db

    async def initiate_oauth_flow(self, user_id: str, provider: str = "gmail") -> dict:
        """Initiate OAuth flow for email provider"""
        email_provider = self.provider_factory.get_provider(
            provider,
            redis_client=self.redis_client,
            settings=self.settings,
            db=self.db,
        )
        return await email_provider.initiate_oauth(user_id)

    async def handle_oauth_callback(self, request: Request, provider: str) -> dict:
        """Handle OAuth callback"""
        email_provider = self.provider_factory.get_provider(
            provider, redis_client=self.redis_client, settings=self.settings, db=self.db
        )
        return await email_provider.handle_callback(request)

    async def send_email(
        self, account_id: str, to: str, subject: str, body: str
    ) -> dict:

        # Get account to determine provider
        account = (
            self.db.query(UserEmailAccount)
            .filter(UserEmailAccount.id == account_id)
            .first()
        )

        if not account:
            raise ValueError("Email account not found")

        email_provider = self.provider_factory.get_provider(
            str(account.provider),
            redis_client=self.redis_client,
            settings=self.settings,
            db=self.db,
        )

        return await email_provider.send_email(account_id, to, subject, body)
