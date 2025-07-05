import logging
from typing import Annotated
from jose import ExpiredSignatureError
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from psycopg2 import IntegrityError
from requests import Session
from starlette import status

from .exceptions import (
    InvalidTokenPayloadError,
    TokenVerificationError,
)
from .schemas import CreateUserRequest, LoginResponse
from .service import AuthService
from database import get_db
from .dependencies import get_current_user
from .utils import oauth2_bearer
from config import Config

config = Config()
SECRET_KEY = config.SECRET_KEY
ALGORITHM = config.ALGORITHM


router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)
db_dependency = Annotated[Session, Depends(get_db)]


@router.post("/createUser", status_code=status.HTTP_201_CREATED)
async def create_user(
    db: db_dependency, create_user_request: CreateUserRequest
):
    try:

        auth_service = AuthService(db)
        auth_service.create_user(
            username=create_user_request.username,
            password=create_user_request.password,
        )
        logger.info(f"User created successfully !")

    except IntegrityError as e:

        logger.error(f"User creation failed: {e}")
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        )

    except Exception as e:

        logger.error(f"User creation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service temporarily unavailable",
        )


@router.post("/login", response_model=LoginResponse)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: db_dependency,
):
    """
    Authenticates user credentials and returns a JWT token if valid.
    """

    try:
        auth_service = AuthService(db)
        login_response = await auth_service.login(
            username=form_data.username, password=form_data.password
        )
        logger.info(f"User {form_data.username} logged in successfully")
        return login_response

    except Exception as e:
        logger.error(f"Login error for user {form_data.username}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service temporarily unavailable",
        )


@router.get("/refreshToken")
async def refresh_token(
    db: db_dependency,
    refresh_token: Annotated[str, Depends(oauth2_bearer)],
):
    try:

        auth_service = AuthService(db)
        refresh_token_response = auth_service.refresh_token(
            refresh_token=refresh_token
        )
        logger.info("Refresh token successful")
        return refresh_token_response

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
            detail="Authentication service temporarily unavailable",
        )


@router.get("/getCurrUser", status_code=status.HTTP_200_OK)
async def user(
    user: Annotated[dict, Depends(get_current_user)], db: db_dependency
):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    return {"User": user}
