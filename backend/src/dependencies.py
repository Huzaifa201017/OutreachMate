from fastapi import Request, Depends
from redis.asyncio.client import Redis
from typing import Annotated
from fastapi.params import Depends
from typing import Annotated
import logging

from src.exceptions import InvalidTokenError
from src.auth.utils import oauth2_bearer, verify_token

logger = logging.getLogger(__name__)


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
