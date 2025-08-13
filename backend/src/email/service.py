import base64
import json
import logging
from typing import cast

from fastapi import Request
from redis.asyncio import Redis
from sqlalchemy.orm import Session
from src.email.providers.gmail import GmailProvider
from src.email.providers.provider_factory import ProviderFactory
from src.email.schemas import SendEmailRequest
from src.exceptions import AccountNotFoundError, EmailSendError
from src.models import UserEmailAccount
from src.settings import Settings

logger = logging.getLogger(__name__)


class EmailService:

    def __init__(self, redis_client: Redis, settings: Settings, db: Session):
        self.provider_factory = ProviderFactory()
        self.redis_client = redis_client
        self.settings = settings
        self.db = db

    async def initiate_oauth_flow(
        self, user_id: str, provider: str = "gmail"
    ) -> dict:
        """Initiate OAuth flow for email provider"""
        email_provider = self.provider_factory.get_provider(
            provider,
            redis_client=self.redis_client,
            settings=self.settings,
            db=self.db,
        )
        return await email_provider.initiate_oauth(user_id)

    async def handle_oauth_callback(
        self, request: Request, provider: str
    ) -> dict:
        """Handle OAuth callback"""
        email_provider = self.provider_factory.get_provider(
            provider,
            redis_client=self.redis_client,
            settings=self.settings,
            db=self.db,
        )
        return await email_provider.handle_callback(request)

    async def send_email(
        self, user_id: str, request: SendEmailRequest
    ) -> dict:
        """
        Send email using specified email account

        Args:
            user_id: User identifier for authorization
            account_id: Email account identifier
            to: Recipient email address
            subject: Email subject
            body: Email body content

        Returns:
            Dictionary containing success status and email details

        Raises:
            AccountNotFoundError: If email account is not found or unauthorized
            EmailSendError: If email sending fails
        """

        account_id = request.account_id
        to_email = request.to_email
        body = request.body
        subject = request.subject
        display_name = request.display_name

        try:
            logger.info(
                f"Sending email from account: {account_id} for user: {user_id} to: {to_email}"
            )

            # Step 1: Retrieve and validate email account with authorization check
            account = (
                self.db.query(UserEmailAccount)
                .filter(
                    UserEmailAccount.id == request.account_id,
                    UserEmailAccount.user_id == user_id,
                )
                .first()
            )

            if not account:
                logger.warning(
                    f"Email account not found or unauthorized: {account_id} for user: {user_id}"
                )
                raise AccountNotFoundError(account_id)

            # Step 2: Get appropriate email provider instance
            email_provider = self.provider_factory.get_provider(
                str(account.provider),
                redis_client=self.redis_client,
                settings=self.settings,
                db=self.db,
            )

            # Step 3: Prepare sender information from account data
            sender = f"{display_name} <{account.email}>"

            # Step 4: Send email through provider
            result = await email_provider.send_email(
                account_id, to_email, sender, subject, body
            )

            logger.info(
                f"Email sent successfully from account: {account_id} to: {to_email}"
            )

            return result

        except AccountNotFoundError:
            # Re-raise known exceptions without wrapping
            raise
        except Exception as e:
            logger.exception(
                f"Failed to send email from account: {account_id} to: {to_email}"
            )
            raise EmailSendError(to_email) from e

    async def handle_gmail_push_notification(self, request: Request) -> None:
        """Handle Gmail push notifications for reply detection"""

        logger.info("Received Gmail push notification")

        # Step 1: Parse Pub/Sub message
        body = await request.json()
        message = body.get("message", {})
        if not message:
            logger.warning("Invalid push notification format")
            return

        # Step 2: Decode message data
        message_data = base64.b64decode(message.get("data", "")).decode(
            "utf-8"
        )
        notification_data = json.loads(message_data)

        email_address = notification_data.get("emailAddress")
        history_id = notification_data.get("historyId")

        logger.info(
            f"Processing notification for email: {email_address}, historyId: {history_id}"
        )

        # Step 3: Find account by email
        account = (
            self.db.query(UserEmailAccount)
            .filter(UserEmailAccount.email == email_address)
            .first()
        )

        if not account:
            logger.warning(f"Account not found for email: {email_address}")
            return

        # Step 4: Process the notification for replies
        email_provider: GmailProvider = cast(
            GmailProvider,
            self.provider_factory.get_provider(
                str(account.provider),
                redis_client=self.redis_client,
                settings=self.settings,
                db=self.db,
            ),
        )
        await email_provider.process_gmail_notification(account, history_id)
