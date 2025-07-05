from datetime import datetime, timedelta, timezone
import logging
from typing import Optional
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from config import Config
from jose import ExpiredSignatureError, jwt


config = Config()
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/login")
logger = logging.getLogger(__name__)


def get_password_hash(password: str) -> str:
    return bcrypt_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt_context.verify(plain_password, hashed_password)


def create_token(
    username: str, user_id: int, expires_delta: timedelta, type: str
):
    """
    Generates a JWT access token with an expiration time.
    """
    encode = {"sub": username, "id": user_id}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({"exp": expires, "token_type": type})
    return jwt.encode(encode, config.SECRET_KEY, algorithm=config.ALGORITHM)


def verify_token(token: str, token_type: str) -> Optional[dict]:
    """
    Verify and decode a JWT token

    Args:
        token: JWT token string
        token_type: Expected token type ('access' or 'refresh')

    Returns:
        Token payload if valid, None otherwise
    """
    try:
        payload = jwt.decode(
            token,
            config.SECRET_KEY,
            algorithms=[config.ALGORITHM],
        )

        # Verify token type
        if payload.get("token_type") != token_type:
            return None

        return payload

    except ExpiredSignatureError as e:
        logger.warning(f"Token has expired: {str(e)}")
        raise ExpiredSignatureError("Token has expired")
