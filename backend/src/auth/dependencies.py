from fastapi import Request, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi_mail import ConnectionConfig
from redis.asyncio.client import Redis
from typing import Annotated
from fastapi.params import Depends
from typing import Annotated
import logging

from sqlalchemy.orm import Session

from src.database import get_db
from src.config import AppConfig
from src.dependencies import get_config, get_system_mail_config
from src.dependencies import get_redis
from src.auth.service import AuthService
from src.auth.constants import AuthConstants
from src.auth.utils import verify_token

logger = logging.getLogger(__name__)

oauth2_bearer = OAuth2PasswordBearer(tokenUrl=AuthConstants.LOGIN_URL)


def get_current_user(
    token: Annotated[str, Depends(oauth2_bearer)],
    app_config: Annotated[AppConfig, Depends(get_config)],
):
    """
    Decodes the JWT token and retrieves user details.
    Raises an exception if the token is invalid or expired.
    """

    email, user_id = verify_token(
        token, AuthConstants.ACCESS_TOKEN_TYPE, app_config
    )

    return {"email": email, "id": user_id}


def get_auth_service(
    db: Annotated[Session, Depends(get_db)],
    redis_client: Annotated[Redis, Depends(get_redis)],
    app_config: Annotated[AppConfig, Depends(get_config)],
    mail_config: Annotated[ConnectionConfig, Depends(get_system_mail_config)],
) -> AuthService:
    return AuthService(
        db=db,
        redis_client=redis_client,
        config=app_config,
        system_mail_config=mail_config,
    )
