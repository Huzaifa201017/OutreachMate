from typing import Annotated
from fastapi.params import Depends
from typing import Annotated
import logging

from exceptions import InvalidTokenError
from .utils import oauth2_bearer, verify_token
from fastapi import Depends

logger = logging.getLogger(__name__)


def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    """
    Decodes the JWT token and retrieves user details.
    Raises an exception if the token is invalid or expired.
    """

    payload = verify_token(token, "access")

    if payload is None:
        raise InvalidTokenError("Token verification failed")

    username = payload.get("sub")
    user_id = payload.get("id")

    if not username or not user_id:
        raise InvalidTokenError("Missing user data in token")

    return {"username": username, "id": user_id}
