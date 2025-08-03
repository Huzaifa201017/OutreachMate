import base64
import logging
from email.mime.text import MIMEText
from typing import Dict, Any

from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials

from src.exceptions import CredentialsRefreshError
from .constants import EmailConstants

logger = logging.getLogger(__name__)


def generate_oauth_state_key(state: str) -> str:
    """Generate Redis key for OAuth state storage"""

    return f"{EmailConstants.OAUTH_STATE_PREFIX}:{state}"


def credentials_to_dict(credentials: Credentials) -> Dict[str, Any]:
    """Convert Google OAuth2 Credentials to dictionary"""
    return {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "granted_scopes": (
            list(credentials.granted_scopes) if credentials.granted_scopes else []
        ),
    }


def dict_to_credentials(credentials_dict: Dict[str, Any]) -> Credentials:
    """Convert dictionary to Google OAuth2 Credentials"""
    return Credentials(
        token=credentials_dict["token"],
        refresh_token=credentials_dict["refresh_token"],
        token_uri=credentials_dict["token_uri"],
        client_id=credentials_dict["client_id"],
        client_secret=credentials_dict["client_secret"],
        scopes=credentials_dict.get("granted_scopes", []),
    )


def create_mime_message(to: str, subject: str, body: str, sender: str) -> str:
    """Create and encode MIME message for Gmail API"""
    message = MIMEText(body)
    message["to"] = to
    message["subject"] = subject
    message["from"] = sender

    return base64.urlsafe_b64encode(message.as_bytes()).decode()


def refresh_credentials_if_needed(
    credentials: Credentials, account, db_session
) -> Credentials:
    """Refresh OAuth credentials if expired and update database"""

    if not credentials.expired:
        return credentials

    try:
        # Step 1: Refresh expired credentials
        logger.info(f"Refreshing expired credentials for account: {account.id}")
        credentials.refresh(GoogleRequest())

        # Step 2: Update stored credentials in database
        updated_credentials_dict = credentials_to_dict(credentials)
        account.credentials = updated_credentials_dict
        db_session.commit()

        logger.info(f"Successfully refreshed credentials for account: {account.id}")
        return credentials

    except Exception as e:
        logger.exception(f"Failed to refresh credentials for account: {account.id}")
        raise CredentialsRefreshError() from e
