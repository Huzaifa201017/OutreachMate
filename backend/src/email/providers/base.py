from abc import ABC, abstractmethod
from typing import Dict, Any

from fastapi import Request
from redis.asyncio import Redis
from sqlalchemy.orm.session import Session

from src.settings import Settings


class BaseEmailProvider(ABC):
    """Abstract base class for email providers"""

    def __init__(self, redis_client: Redis, settings: Settings, db: Session):
        self.redis_client = redis_client
        self.settings = settings
        self.db = db

    @abstractmethod
    async def initiate_oauth(self, user_id: str) -> Dict[str, str]:
        """Initiate OAuth flow and return auth URL"""
        pass

    @abstractmethod
    async def handle_callback(self, request: Request) -> Dict[str, Any]:
        """Handle OAuth callback and store credentials"""
        pass

    @abstractmethod
    async def send_email(
        self, account_id: str, to: str, subject: str, body: str
    ) -> Dict[str, Any]:
        """Send email using stored credentials"""
        pass
