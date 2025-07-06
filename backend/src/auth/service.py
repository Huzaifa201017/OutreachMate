import logging
from sqlalchemy.exc import IntegrityError
from requests import Session

from exceptions import (
    InvalidCredentialsError,
    InvalidTokenError,
    UserAlreadyExistsError,
)
from .schemas import LoginResponse, RefreshTokenResponse

from .utils import (
    create_token,
    get_password_hash,
    verify_password,
    verify_token,
)
from models import Users
from config import Config

config = Config()
SECRET_KEY = config.SECRET_KEY
ALGORITHM = config.ALGORITHM

logger = logging.getLogger(__name__)


class AuthService:
    """Service class for authentication operations"""

    def __init__(self, db: Session):
        self.db = db

    def create_user(self, username: str, password: str):
        """
        Creates a new user with a hashed password.
        Returns the created user model.
        """
        try:
            hashed_password = get_password_hash(password)
            user = Users(username=username, hashed_password=hashed_password)
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)

        except IntegrityError as e:
            logger.exception("User creation failed due to integrity error.")
            self.db.rollback()
            raise UserAlreadyExistsError() from e

    def _authenticate_user(self, username: str, password: str):
        """
        Verifies the username and password against stored hashed password.
        Returns the user if authentication is successful, otherwise returns False.
        """
        user = self.db.query(Users).filter(Users.username == username).first()
        if not user:
            logger.warning(
                f"Authentication failed: user '{username}' not found."
            )
            raise InvalidCredentialsError()

        if not verify_password(password, user.hashed_password):
            logger.warning(
                f"Authentication failed: invalid password for user '{username}'."
            )
            raise InvalidCredentialsError()

        logger.debug(f"User '{username}' successfully authenticated.")
        return user

    async def login(self, username: str, password: str) -> LoginResponse:
        """
        Authenticates user credentials and returns a JWT token if valid.
        """

        user = self._authenticate_user(username, password)

        access_token = create_token(
            username=user.username,
            user_id=user.id,
            expires_delta=config.access_token_expire_delta,
            type="access",
        )
        refresh_token = create_token(
            username=user.username,
            user_id=user.id,
            expires_delta=config.refresh_token_expire_delta,
            type="refresh",
        )

        logger.info(f"Issued new tokens for user '{username}'")

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
            raise InvalidTokenError()

        username = payload.get("sub")
        user_id = payload.get("id")

        if not username or not user_id:
            raise InvalidTokenError()

        new_access_token = create_token(
            username, user_id, config.access_token_expire_delta, "access"
        )

        return RefreshTokenResponse(access_token=new_access_token)
