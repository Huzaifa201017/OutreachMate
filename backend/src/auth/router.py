import logging
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends
from src.auth.dependencies import (
    get_auth_service,
    get_current_user,
    oauth2_bearer,
)
from src.auth.schemas import LoginResponse, RefreshTokenResponse
from starlette import status

from .schemas import (
    CreateUserRequest,
    LoginRequest,
    RefreshTokenRequest,
    VerifyOTPRequest,
    VerifyOTPResponse,
)
from .service import AuthService

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)


@router.post("/createUser", status_code=status.HTTP_201_CREATED)
async def create_user(
    create_user_request: CreateUserRequest,
    background_tasks: BackgroundTasks,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> None:

    await auth_service.create_user(
        create_user_request=create_user_request,
        background_tasks=background_tasks,
    )
    logger.info(f"User created successfully !")


@router.post("/login")
async def login(
    login_request: LoginRequest,
    background_tasks: BackgroundTasks,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> LoginResponse:
    """
    Authenticates user credentials and returns a JWT token if valid.
    """

    login_response = await auth_service.login(
        login_request=login_request, background_tasks=background_tasks
    )
    logger.info(f"User {login_request.email} authenticated successfully")
    return login_response


@router.post("/verifyOTP", response_model=VerifyOTPResponse)
async def verify_otp(
    verify_otp_request: VerifyOTPRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> VerifyOTPResponse:
    verify_otp_response = await auth_service.verify_otp(
        verify_otp_request=verify_otp_request
    )
    logger.info("OTP verification successful")
    return verify_otp_response


@router.get("/refreshToken")
async def refresh_token(
    refresh_token_request: RefreshTokenRequest,
    refresh_token: Annotated[str, Depends(oauth2_bearer)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> RefreshTokenResponse:

    refresh_token_response = await auth_service.refresh_token(
        refresh_token_request=refresh_token_request,
        refresh_token=refresh_token,
    )
    logger.info("Refresh token successful")
    return refresh_token_response


@router.get("/getCurrUser", status_code=status.HTTP_200_OK)
async def user(
    user: Annotated[dict, Depends(get_current_user)],
) -> dict[str, dict[Any, Any]]:
    return {"User": user}
