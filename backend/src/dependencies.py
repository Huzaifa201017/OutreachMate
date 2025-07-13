from fastapi import Request, Depends
from fastapi.security import OAuth2PasswordBearer
from redis.asyncio.client import Redis
from typing import Annotated
from fastapi.params import Depends
from typing import Annotated
import logging

from requests import Session

from src.auth.service import AuthService
from src.database import get_db
from src.auth.constants import AuthConstants
from src.exceptions import InvalidTokenError
from src.auth.utils import verify_token

logger = logging.getLogger(__name__)

oauth2_bearer = OAuth2PasswordBearer(tokenUrl=AuthConstants.LOGIN_URL)


def get_redis(request: Request) -> Redis:
    return request.app.state.redis


def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    """
    Decodes the JWT token and retrieves user details.
    Raises an exception if the token is invalid or expired.
    """

    payload = verify_token(token, "access")

    if payload is None:
        raise InvalidTokenError("Token verification failed")

    email = payload.get("sub")
    user_id = payload.get("id")

    if not email or not user_id:
        raise InvalidTokenError("Missing user data in token")

    return {"email": email, "id": user_id}


def get_auth_service(
    db: Annotated[Session, Depends(get_db)],
    redis_client: Annotated[Redis, Depends(get_redis)],
) -> AuthService:
    return AuthService(db=db, redis_client=redis_client)
