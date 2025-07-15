import logging
import random
import string
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union

from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext
from pydantic import EmailStr
from sqlalchemy.orm import Session
from src.auth.constants import AuthConstants
from src.exceptions import InvalidTokenError, UserNotFoundError
from src.models import Users
from src.settings import Settings

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
logger = logging.getLogger(__name__)


def get_password_hash(password: str) -> str:
    return bcrypt_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt_context.verify(plain_password, hashed_password)


def create_token(
    email: str,
    user_id: int,
    expires_delta: timedelta,
    token_type: str,
    secret_key: str,
    algorithm: str,
) -> str:
    """
    Generates a JWT access token with an expiration time.
    """
    encode = {"sub": email, "id": user_id}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({"exp": expires, "token_type": token_type})

    return jwt.encode(encode, secret_key, algorithm)


def verify_token(
    token: str, token_type: str, secret_key: str, algorithm: str
) -> tuple[str, int]:
    """
    Verify and decode a JWT token
    """
    try:
        payload = jwt.decode(
            token,
            secret_key,
            algorithm,
        )

        # Verify token type
        if payload.get("token_type") != token_type:
            logger.warning(
                f"Token type mismatch: expected {token_type}, got {payload.get('token_type')}"
            )
            raise InvalidTokenError()

        # Step 2: Extract and validate user information
        email = payload.get("sub")
        user_id = payload.get("id")

        if email is None or user_id is None:
            logger.error("Malformed token payload - missing required claims")
            raise InvalidTokenError()

        return str(email), int(user_id)

    except ExpiredSignatureError as e:
        logger.exception(f"Token has expired")
        raise InvalidTokenError() from e

    except JWTError as e:
        logger.exception(f"Token verification failed: {str(e)}")
        raise InvalidTokenError() from e


def generate_otp(length=6) -> EmailStr:
    return "".join(random.choices(string.digits, k=length))


async def send_email_with_template(
    subject: str,
    recipients: Union[EmailStr, List[EmailStr]],
    template_name: str,
    template_body: Dict,
    mail_config: ConnectionConfig,
) -> None:
    """
    Sends an email using a Jinja2 template via FastAPI-Mail.
    """
    if isinstance(recipients, str):
        recipients = [recipients]

    message = MessageSchema(
        subject=subject,
        recipients=recipients,
        template_body=template_body,
        subtype=MessageType.html,
    )

    fm = FastMail(mail_config)
    await fm.send_message(message, template_name=template_name)
    logger.info(f"Email sent to {recipients} with template '{template_name}'")


def create_tokens(
    email: str, user_id: int, settings: Settings
) -> tuple[str, str]:
    """
    Utility to create access and refresh tokens.
    """
    access_token = create_token(
        email=email,
        user_id=user_id,
        expires_delta=settings.access_token_expire_delta,
        token_type=AuthConstants.ACCESS_TOKEN_TYPE,
        secret_key=settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    refresh_token = create_token(
        email=email,
        user_id=user_id,
        expires_delta=settings.refresh_token_expire_delta,
        token_type=AuthConstants.REFRESH_TOKEN_TYPE,
        secret_key=settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    return access_token, refresh_token


async def set_cache_with_expiry(
    redis_client, key: str, value: str, expiry_duration: timedelta
) -> None:
    """
    Utility to store key:value in the cache.
    """
    await redis_client.setex(
        key,
        expiry_duration,
        value,
    )


async def get_cache_value(redis_client, key: str) -> Any:
    """
    Utility to get cache value by key.
    """
    return await redis_client.get(key)


def get_user_by_email(db: Session, email: str) -> Users:
    """
    Fetch user by email from the database.
    """
    user = db.query(Users).filter(Users.email == email).first()
    if not user:
        logger.warning(f"User not found: {email}")
        raise UserNotFoundError()

    return user
