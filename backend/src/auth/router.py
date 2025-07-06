import logging
from typing import Annotated
from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm
from requests import Session
from starlette import status
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

    auth_service = AuthService(db)
    auth_service.create_user(
        username=create_user_request.username,
        password=create_user_request.password,
    )
    logger.info(f"User created successfully !")


@router.post("/login", response_model=LoginResponse)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: db_dependency,
):
    """
    Authenticates user credentials and returns a JWT token if valid.
    """

    auth_service = AuthService(db)
    login_response = await auth_service.login(
        username=form_data.username, password=form_data.password
    )
    logger.info(f"User {form_data.username} logged in successfully")
    return login_response


@router.get("/refreshToken")
async def refresh_token(
    db: db_dependency,
    refresh_token: Annotated[str, Depends(oauth2_bearer)],
):

    auth_service = AuthService(db)
    refresh_token_response = auth_service.refresh_token(
        refresh_token=refresh_token
    )
    logger.info("Refresh token successful")
    return refresh_token_response


@router.get("/getCurrUser", status_code=status.HTTP_200_OK)
async def user(
    user: Annotated[dict, Depends(get_current_user)], db: db_dependency
):
    return {"User": user}
