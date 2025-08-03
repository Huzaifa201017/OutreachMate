import logging
import uuid
from typing import Dict, Any

from fastapi import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from redis.asyncio import Redis
from sqlalchemy.orm import Session

from src.email.constants import EmailConstants
from src.email.providers.base import BaseEmailProvider
from src.email.utils import (
    generate_oauth_state_key,
    credentials_to_dict,
    refresh_credentials_if_needed,
    dict_to_credentials,
    create_mime_message,
)
from src.exceptions import (
    EmailNotFoundError,
    AccountNotFoundError,
    OAuthInitiationError,
    OAuthCallbackError,
    InvalidOAuthStateException,
    CredentialsRefreshError,
    EmailSendError,
)
from src.models import UserEmailAccount
from src.settings import Settings

logger = logging.getLogger(__name__)


class GmailProvider(BaseEmailProvider):

    # TODO: Replace with constant enums
    SCOPES = [
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid",
    ]

    def __init__(self, redis_client: Redis, settings: Settings, db: Session):
        super().__init__(redis_client, settings, db)

    async def initiate_oauth(self, user_id: str) -> Dict[str, Any]:
        """
        Initiate OAuth flow for Gmail authentication

        Args:
            user_id: User identifier

        Returns:
            Dictionary containing auth URL, state, and message

        Raises:
            OAuthInitiationError: If OAuth flow initiation fails
        """
        try:
            logger.info(f"Initiating Gmail OAuth flow for user: {user_id}")

            # Step 1: Create OAuth flow with client secrets
            flow = Flow.from_client_secrets_file(
                self.settings.GOOGLE_CLIENT_SECRET_FILE, scopes=self.SCOPES
            )
            flow.redirect_uri = self.settings.REDIRECT_URI

            # Step 2: Generate authorization URL with required parameters
            auth_url, state = flow.authorization_url(
                access_type=EmailConstants.OAUTH_ACCESS_TYPE,
                include_granted_scopes="true",
                prompt="consent",
            )

            # Step 3: Store state in Redis with expiration
            state_key = generate_oauth_state_key(state)
            await self.redis_client.setex(
                state_key, self.settings.oauth2_state_expiry_delta, user_id
            )

            logger.info(
                f"OAuth flow initiated successfully for user: {user_id}, state: {state}"
            )

            return {
                "auth_url": auth_url,
                "state": state,
                "message": "Redirect user to auth_url to complete OAuth flow",
            }

        except Exception as e:
            logger.exception(f"Failed to initiate Gmail OAuth flow for user: {user_id}")
            raise OAuthInitiationError(EmailConstants.GMAIL) from e

    async def handle_callback(self, request: Request) -> Dict[str, Any]:
        """
        Handle OAuth callback and exchange code for tokens

        Args:
            request: FastAPI request object containing OAuth callback parameters

        Returns:
            Dictionary containing success message, email, and account ID

        Raises:
            InvalidOAuthStateException: If OAuth state is invalid
            EmailNotFoundError: If user email cannot be retrieved
            OAuthCallbackError: If callback handling fails
        """
        try:
            state = request.query_params.get("state")
            logger.info(f"Handling Gmail OAuth callback with state: {state}")

            # Step 1: Validate state and retrieve user ID from Redis
            state_key = generate_oauth_state_key(state)
            user_id = await self.redis_client.get(state_key)

            if not user_id:
                logger.warning(f"Invalid or expired OAuth state: {state}")
                raise InvalidOAuthStateException(state)

            # Step 2: Clean up state from Redis
            await self.redis_client.delete(state_key)
            logger.info(f"OAuth state validated and cleaned up for user: {user_id}")

            # Step 3: Exchange authorization code for tokens
            flow = Flow.from_client_secrets_file(
                self.settings.GOOGLE_CLIENT_SECRET_FILE, scopes=self.SCOPES, state=state
            )
            flow.redirect_uri = self.settings.REDIRECT_URI

            flow.fetch_token(authorization_response=str(request.url))
            credentials = flow.credentials
            logger.info(
                f"Successfully exchanged authorization code for tokens, user: {user_id}"
            )

            # Step 4: Convert credentials to dictionary for storage
            credentials_dict = credentials_to_dict(credentials)

            # Step 5: Retrieve user email from Google OAuth2 API
            email = await self._get_user_email(credentials)

            # Step 6: Create or update user email account
            account = await self._create_or_update_account(
                user_id, email, credentials_dict
            )

            logger.info(
                f"Gmail account processed successfully for user: {user_id}, email: {email}"
            )

            return {
                "message": f"Gmail account {'updated' if account['is_existing'] else 'added'} successfully",
                "email": email,
                "account_id": account["id"],
            }

        except (InvalidOAuthStateException, EmailNotFoundError):
            # Re-raise known exceptions without wrapping
            raise
        except Exception as e:
            logger.exception("Failed to handle Gmail OAuth callback")
            raise OAuthCallbackError(EmailConstants.GMAIL) from e

    async def _get_user_email(self, credentials) -> str:
        """
        Retrieve user email from Google OAuth2 API

        Args:
            credentials: Google OAuth2 credentials

        Returns:
            User email address

        Raises:
            EmailNotFoundError: If email cannot be retrieved
        """
        try:
            # Step 1: Build OAuth2 service
            service = build("oauth2", "v2", credentials=credentials)

            # Step 2: Get user info
            user_info = service.userinfo().get().execute()
            email = user_info.get("email")

            if not email:
                logger.warning(f"Unable to get email from user info: {user_info}")
                raise EmailNotFoundError()

            logger.info(f"Successfully retrieved user email: {email}")
            return email

        except EmailNotFoundError:
            raise
        except Exception as e:
            logger.exception("Failed to retrieve user email from Google API")
            raise EmailNotFoundError() from e

    async def _create_or_update_account(
        self, user_id: str, email: str, credentials_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create new account or update existing account with credentials

        Args:
            user_id: User identifier
            email: User email address
            credentials_dict: OAuth credentials dictionary

        Returns:
            Dictionary containing account ID and whether it's existing
        """
        # Step 1: Check if account already exists
        existing_account = (
            self.db.query(UserEmailAccount)
            .filter(
                UserEmailAccount.email == email, UserEmailAccount.user_id == user_id
            )
            .first()
        )

        if existing_account:
            # Step 2a: Update existing account
            logger.info(f"Updating existing Gmail account: {existing_account.id}")
            existing_account.credentials = credentials_dict
            self.db.commit()

            return {"id": existing_account.id, "is_existing": True}
        else:
            # Step 2b: Create new account
            logger.info(
                f"Creating new Gmail account for user: {user_id}, email: {email}"
            )
            new_account = UserEmailAccount(
                id=str(uuid.uuid4()),
                user_id=user_id,
                email=email,
                provider=EmailConstants.GMAIL,
                credentials=credentials_dict,
            )

            self.db.add(new_account)
            self.db.commit()
            self.db.refresh(new_account)

            return {"id": new_account.id, "is_existing": False}

    def _get_gmail_service(self, account_id: str):
        """
        Get authenticated Gmail service for account

        Args:
            account_id: Email account identifier

        Returns:
            Authenticated Gmail service instance

        Raises:
            AccountNotFoundError: If account is not found
            CredentialsRefreshError: If credentials refresh fails
        """
        logger.info(f"Getting Gmail service for account: {account_id}")

        # Step 1: Retrieve account from database
        account = (
            self.db.query(UserEmailAccount)
            .filter(UserEmailAccount.id == account_id)
            .first()
        )

        if not account:
            logger.warning(f"Email account not found: {account_id}")
            raise AccountNotFoundError(account_id)

        # Step 2: Convert stored credentials to Credentials object
        credentials_dict = account.credentials
        credentials = dict_to_credentials(credentials_dict)

        # Step 3: Refresh credentials if expired
        credentials = refresh_credentials_if_needed(credentials, account, self.db)

        # Step 4: Build and return Gmail service
        logger.info(f"Successfully created Gmail service for account: {account_id}")
        return build("gmail", "v1", credentials=credentials)

    async def send_email(
        self, account_id: str, to: str, sender: str, subject: str, body: str
    ) -> Dict[str, Any]:
        """
        Send email using Gmail API

        Args:
            account_id: Email account identifier
            to: Recipient email address
            sender: Sender email address
            subject: Email subject
            body: Email body content

        Returns:
            Dictionary containing success message and email details

        Raises:
            AccountNotFoundError: If account is not found
            EmailSendError: If email sending fails
        """
        try:
            logger.info(f"Sending email from account: {account_id} to: {to}")

            # Step 1: Get authenticated Gmail service
            service = self._get_gmail_service(account_id)

            # Step 2: Create MIME message
            raw_message = create_mime_message(to, subject, body, sender)

            # Step 3: Send email via Gmail API
            result = (
                service.users()
                .messages()
                .send(userId="me", body={"raw": raw_message})
                .execute()
            )

            logger.info(
                f"Email sent successfully from account: {account_id} to: {to}, message_id: {result.get('id')}"
            )

            return {"message": "Email sent successfully", "details": result}

        except (AccountNotFoundError, CredentialsRefreshError):
            # Re-raise known exceptions without wrapping
            raise
        except Exception as e:
            logger.exception(
                f"Failed to send email from account: {account_id} to: {to}"
            )
            raise EmailSendError(to) from e
