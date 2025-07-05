from datetime import timedelta

from requests import Session

from .exceptions import (
    InvalidTokenPayloadError,
    TokenVerificationError,
)
from .schemas import LoginResponse, RefreshTokenResponse

from .utils import (
    create_token,
    get_password_hash,
    verify_password,
    verify_token,
)
from fastapi import HTTPException
from starlette import status
from models import Users
from config import Config

config = Config()
SECRET_KEY = config.SECRET_KEY
ALGORITHM = config.ALGORITHM


class AuthService:
    """Service class for authentication operations"""

    def __init__(self, db: Session):
        self.db = db

    def create_user(self, username: str, password: str):
        """
        Creates a new user with a hashed password.
        Returns the created user model.
        """
        hashed_password = get_password_hash(password)
        user = Users(username=username, hashed_password=hashed_password)
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

    def _authenticate_user(self, username: str, password: str):
        """
        Verifies the username and password against stored hashed password.
        Returns the user if authentication is successful, otherwise returns False.
        """
        user = self.db.query(Users).filter(Users.username == username).first()
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None

        return user

    async def login(self, username: str, password: str) -> LoginResponse:
        """
        Authenticates user credentials and returns a JWT token if valid.
        """

        user = self._authenticate_user(username, password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        access_token = create_token(
            username=user.username,
            user_id=user.id,
            expires_delta=timedelta(minutes=1),
            type="access",
        )
        refresh_token = create_token(
            username=user.username,
            user_id=user.id,
            expires_delta=timedelta(minutes=2),
            type="refresh",
        )
        return LoginResponse(
            access_token=access_token, refresh_token=refresh_token
        )

    def refresh_token(self, refresh_token: str) -> RefreshTokenResponse:
        """
        Refreshes the access token using the provided refresh token.
        Returns a new access token if the refresh token is valid.
        """

        payload = verify_token(refresh_token, "refresh")
        if payload is None:
            raise TokenVerificationError("Token verification failed")

        username = payload.get("sub")
        user_id = payload.get("id")

        if not username or not user_id:
            raise InvalidTokenPayloadError("Missing user data in token")

        new_access_token = create_token(
            username, user_id, timedelta(minutes=2), "access"
        )

        return RefreshTokenResponse(access_token=new_access_token)
