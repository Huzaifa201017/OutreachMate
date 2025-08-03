import logging
import uuid

from fastapi import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from redis.asyncio import Redis
from sqlalchemy.orm import Session

from src.email.providers.base import BaseEmailProvider
from src.exceptions import UnknowError, InvalidOAuthStateError, EmailNotFoundError
from src.models import UserEmailAccount
from src.settings import Settings

logger = logging.getLogger(__name__)


class GmailProvider(BaseEmailProvider):

    SCOPES = [
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid",
    ]

    def __init__(self, redis_client: Redis, settings: Settings, db: Session):
        super().__init__(redis_client, settings, db)

    async def initiate_oauth(self, user_id: str) -> dict:
        """Initiate Gmail OAuth flow"""
        try:

            # Create OAuth flow
            flow = Flow.from_client_secrets_file(
                "client_secret.json", scopes=self.SCOPES
            )
            flow.redirect_uri = self.settings.REDIRECT_URI

            # Generate authorization URL
            auth_url, state = flow.authorization_url(
                access_type="offline",
                include_granted_scopes="true",
                prompt="consent",
            )

            await self.redis_client.setex(f"oauth_state:{state}", 3600, user_id)

            return {
                "auth_url": auth_url,
                "state": state,
                "message": "Redirect user to auth_url to complete OAuth flow",
            }

        except Exception as e:
            logger.exception("Failed to initiate OAuth flow", exc_info=True)
            raise UnknowError from e

    async def handle_callback(self, request: Request) -> dict:
        """Handle OAuth callback from Google"""
        try:
            state = request.query_params.get("state")

            # Get state data from Redis or memory
            user_id = await self.redis_client.get(f"oauth_state:{state}")
            if not user_id:
                logger.warning(f"Invalid state: {state}")
                raise InvalidOAuthStateError()

            # Clean up state
            await self.redis_client.delete(f"oauth_state:{state}")

            # Exchange code for tokens
            flow = Flow.from_client_secrets_file(
                "client_secret.json", scopes=self.SCOPES, state=state
            )
            flow.redirect_uri = self.settings.REDIRECT_URI

            # Use full authorization response URL to fetch tokens
            flow.fetch_token(authorization_response=str(request.url))
            credentials = flow.credentials

            # Convert to dict
            credentials_dict = {
                "token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "token_uri": credentials.token_uri,
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "granted_scopes": credentials.granted_scopes,
            }

            # Get user's email
            service = build("oauth2", "v2", credentials=credentials)
            user_info = service.userinfo().get().execute()
            email = user_info.get("email")

            if not email:
                logger.warning(f"Unable to get email from User Info: {user_info}")
                raise EmailNotFoundError()

            # Check if account exists
            existing_account = (
                self.db.query(UserEmailAccount)
                .filter(
                    UserEmailAccount.email == email, UserEmailAccount.user_id == user_id
                )
                .first()
            )

            if existing_account:

                # Update existing
                existing_account.credentials = credentials_dict
                self.db.commit()

                return {
                    "message": "Gmail account updated successfully",
                    "email": email,
                    "account_id": existing_account.id,
                }

            else:

                # Create new
                new_account = UserEmailAccount(
                    id=str(uuid.uuid4()),
                    user_id=user_id,
                    email=email,
                    provider="gmail",
                    credentials=credentials_dict,
                )

                self.db.add(new_account)
                self.db.commit()
                self.db.refresh(new_account)

                return {
                    "message": "Gmail account added successfully",
                    "email": email,
                    "account_id": new_account.id,
                }

        except (InvalidOAuthStateError, EmailNotFoundError):
            # Don't handle — let these bubble up
            raise
        except Exception as e:
            logger.exception("Failed to handle OAuth callback", exc_info=True)
            raise UnknowError from e
