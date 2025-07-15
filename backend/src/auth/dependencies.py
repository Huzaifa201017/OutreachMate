import logging
from typing import Annotated, Any

from fastapi import Depends
from fastapi.params import Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi_mail import ConnectionConfig
from redis.asyncio.client import Redis
from sqlalchemy.orm import Session
from src.auth.constants import AuthConstants
from src.auth.service import AuthService
from src.auth.utils import verify_token
from src.database import get_db
from src.dependencies import get_redis, get_settings, get_system_mail_config
from src.settings import Settings

logger = logging.getLogger(__name__)

oauth2_bearer = OAuth2PasswordBearer(tokenUrl=AuthConstants.LOGIN_URL)


def get_current_user(
    token: Annotated[str, Depends(oauth2_bearer)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, str | Any]:
    """
    Decodes the JWT token and retrieves user details.
    Raises an exception if the token is invalid or expired.
    """

    email, user_id = verify_token(
        token,
        AuthConstants.ACCESS_TOKEN_TYPE,
        settings.SECRET_KEY,
        settings.ALGORITHM,
    )

    return {"email": email, "id": user_id}


def get_auth_service(
    db: Annotated[Session, Depends(get_db)],
    redis_client: Annotated[Redis, Depends(get_redis)],
    settings: Annotated[Settings, Depends(get_settings)],
    mail_config: Annotated[ConnectionConfig, Depends(get_system_mail_config)],
) -> AuthService:
    return AuthService(
        db=db,
        redis_client=redis_client,
        settings=settings,
        system_mail_config=mail_config,
    )
