import logging
from typing import Annotated
from fastapi import APIRouter, BackgroundTasks, Depends
from requests import Session
from starlette import status
from .schemas import (
    CreateUserRequest,
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    VerifyOTPRequest,
    VerifyOTPResponse,
)
from .service import AuthService
from src.database import get_db
from src.dependencies import get_current_user, get_redis
from .utils import oauth2_bearer
from redis.asyncio.client import Redis


router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)


@router.post("/createUser", status_code=status.HTTP_201_CREATED)
async def create_user(
    create_user_request: CreateUserRequest,
    background_tasks: BackgroundTasks,
    db: Annotated[Session, Depends(get_db)],
    redis_client: Annotated[Redis, Depends(get_redis)],
):

    auth_service = AuthService(db, redis_client)
    await auth_service.create_user(
        create_user_request=create_user_request,
        background_tasks=background_tasks,
    )
    logger.info(f"User created successfully !")


@router.post("/login")
async def login(
    login_request: LoginRequest,
    background_tasks: BackgroundTasks,
    db: Annotated[Session, Depends(get_db)],
    redis_client: Annotated[Redis, Depends(get_redis)],
):
    """
    Authenticates user credentials and returns a JWT token if valid.
    """

    auth_service = AuthService(db, redis_client)
    login_response = await auth_service.login(
        login_request=login_request, background_tasks=background_tasks
    )
    logger.info(f"User {login_request.email} authenticated successfully")
    return login_response


@router.post("/verifyOTP", response_model=VerifyOTPResponse)
async def verify_otp(
    verify_otp_request: VerifyOTPRequest,
    db: Annotated[Session, Depends(get_db)],
    redis_client: Annotated[Redis, Depends(get_redis)],
):
    auth_service = AuthService(db, redis_client)
    verify_otp_response = await auth_service.verify_otp(
        verify_otp_request=verify_otp_request
    )
    logger.info("OTP verification successful")
    return verify_otp_response


@router.get("/refreshToken")
async def refresh_token(
    refresh_token_request: RefreshTokenRequest,
    refresh_token: Annotated[str, Depends(oauth2_bearer)],
    db: Annotated[Session, Depends(get_db)],
    redis_client: Annotated[Redis, Depends(get_redis)],
):

    auth_service = AuthService(db, redis_client)
    refresh_token_response = await auth_service.refresh_token(
        refresh_token_request=refresh_token_request,
        refresh_token=refresh_token,
    )
    logger.info("Refresh token successful")
    return refresh_token_response


@router.get("/getCurrUser", status_code=status.HTTP_200_OK)
async def user(
    user: Annotated[dict, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    return {"User": user}
