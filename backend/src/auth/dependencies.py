from typing import Annotated
from fastapi.params import Depends
from typing import Annotated
import logging
from .exceptions import (
    InvalidTokenPayloadError,
    TokenVerificationError,
)
from .utils import oauth2_bearer, verify_token
from fastapi import Depends, HTTPException
from jose import ExpiredSignatureError
from starlette import status

logger = logging.getLogger(__name__)


def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    """
    Decodes the JWT token and retrieves user details.
    Raises an exception if the token is invalid or expired.
    """
    try:

        payload = verify_token(token, "access")

        if payload is None:
            raise TokenVerificationError("Token verification failed")

        username = payload.get("sub")
        user_id = payload.get("id")

        if not username or not user_id:
            raise InvalidTokenPayloadError("Missing user data in token")

        return {"username": username, "id": user_id}

    except (
        TokenVerificationError,
        InvalidTokenPayloadError,
        ExpiredSignatureError,
    ) as e:

        logger.error(f"Token refresh failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unknown error occurred while getting current user",
        )
