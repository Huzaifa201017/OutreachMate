import logging
from fastapi import BackgroundTasks
from pydantic import EmailStr
from sqlalchemy.exc import IntegrityError
from requests import Session

from src.auth.constants import AuthConstants
from src.exceptions import (
    InvalidCredentialsError,
    InvalidOTPError,
    InvalidTokenError,
    UserAlreadyExistsError,
    UserAlreadyVerifiedError,
    UserNotFoundError,
)
from .schemas import (
    CreateUserRequest,
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    VerifyOTPRequest,
    VerifyOTPResponse,
)
from redis.asyncio.client import Redis
from .utils import (
    create_token,
    generate_otp,
    get_password_hash,
    send_email_with_template,
    verify_password,
    verify_token,
)
from src.models import Users
from src.config import config

logger = logging.getLogger(__name__)


class AuthService:
    """Service class for authentication operations"""

    def __init__(self, db: Session, redis_client: Redis):
        self.db = db
        self.redis_client = redis_client

    async def _send_otp_email(
        self, recipient_email: EmailStr, recipient_name: str
    ):

        try:

            otp = generate_otp()
            template_body = {
                "name": recipient_name,
                "otp": otp,
                "company_name": config.MAIL_FROM_NAME,
                "validity_duration_desc": config.otp_expiry_description,
            }
            logger.info("OTP generated successfully")

            # Store OTP in Redis with expiration
            await self.redis_client.setex(
                name=f"otp:{recipient_email}",
                value=otp,
                time=config.otp_expire_delta,
            )
            logger.info(f"OTP stored in Redis for {recipient_email}")

            await send_email_with_template(
                subject=AuthConstants.OTP_EMAIL_SUBJECT,
                recipients=recipient_email,
                template_name=AuthConstants.OTP_EMAIL_TEMPLATE,
                template_body=template_body,
            )

        except Exception as e:
            logger.exception(f"Failed to send OTP email to {recipient_email}")

    def _authenticate_user(self, email: str, password: str):
        """
        Verifies the email and password against stored hashed password.
        Returns the user if authentication is successful, otherwise returns False.
        """
        user = self.db.query(Users).filter(Users.email == email).first()
        if not user:
            logger.warning(
                f"Authentication failed: Email '{email}' not found."
            )
            raise InvalidCredentialsError()

        if not verify_password(password, user.hashed_password):
            logger.warning(f"Authentication failed: invalid password.")
            raise InvalidCredentialsError()

        logger.debug(f"User '{email}' successfully authenticated.")
        return user

    async def create_user(
        self,
        create_user_request: CreateUserRequest,
        background_tasks: BackgroundTasks,
    ):
        """
        Creates a new user with a hashed password.
        Returns the created user model.
        """
        try:

            hashed_password = get_password_hash(create_user_request.password)
            user = Users(
                first_name=create_user_request.firstname,
                hashed_password=hashed_password,
                email=create_user_request.email,
            )
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)

            background_tasks.add_task(
                self._send_otp_email,
                recipient_email=create_user_request.email,
                recipient_name=create_user_request.firstname,
            )

        except IntegrityError as e:
            logger.exception("User creation failed due to integrity error.")
            self.db.rollback()
            raise UserAlreadyExistsError() from e

    async def login(
        self,
        login_request: LoginRequest,
        background_tasks: BackgroundTasks,
    ) -> LoginResponse:
        """
        Authenticates user credentials and returns a JWT token if valid.
        """

        user = self._authenticate_user(
            login_request.email, login_request.password
        )

        if not user.is_verified:
            logger.warning(f"User '{login_request.email}' is not verified.")

            background_tasks.add_task(
                self._send_otp_email,
                recipient_email=user.email,
                recipient_name=user.first_name,
            )

            return LoginResponse(
                requires_verification=True,
                detail="Email not verified. OTP has been sent to your email.",
            )

        logger.info(f"User '{login_request.email}' verified successfully.")

        access_token = create_token(
            email=user.email,
            user_id=user.id,
            expires_delta=config.access_token_expire_delta,
            type="access",
        )
        refresh_token = create_token(
            email=user.email,
            user_id=user.id,
            expires_delta=config.refresh_token_expire_delta,
            type="refresh",
        )

        await self.redis_client.setex(
            f"refresh_token:{user.id}:{login_request.device_id}",
            config.refresh_token_expire_delta,
            refresh_token,
        )

        logger.info(f"Issued new tokens for user '{user.email}'")

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            requires_verification=False,
            detail="Login Successful",
        )

    async def refresh_token(
        self, refresh_token_request: RefreshTokenRequest, refresh_token: str
    ) -> RefreshTokenResponse:
        """
        Refreshes the access token using the provided refresh token.
        Returns a new access token if the refresh token is valid.
        """

        # Verify the refresh token
        payload = verify_token(refresh_token, "refresh")
        if payload is None:
            raise InvalidTokenError()

        email = payload.get("sub")
        user_id = payload.get("id")

        if not email or not user_id:
            raise InvalidTokenError()

        # Check if the refresh token exists in Redis
        device_id = refresh_token_request.device_id
        old_refresh_token = await self.redis_client.get(
            f"refresh_token:{user_id}:{device_id}",
        )

        if old_refresh_token != refresh_token:
            logger.warning(
                f"Refresh token mismatch for user {email} on device {device_id}, means someone tried to reuse the token"
            )
            raise InvalidTokenError()

        new_access_token = create_token(
            email=email,
            user_id=user_id,
            expires_delta=config.access_token_expire_delta,
            type="access",
        )

        new_refresh_token = create_token(
            email=email,
            user_id=user_id,
            expires_delta=config.refresh_token_expire_delta,
            type="refresh",
        )

        await self.redis_client.setex(
            f"refresh_token:{user_id}:{device_id}",
            config.refresh_token_expire_delta,
            new_refresh_token,
        )
        return RefreshTokenResponse(
            access_token=new_access_token, refresh_token=new_refresh_token
        )

    async def verify_otp(
        self, verify_otp_request: VerifyOTPRequest
    ) -> VerifyOTPResponse:
        """
        Verifies the OTP for a given email address.
        Returns a new  pair of access and refresh tokens if the OTP is valid.
        """

        email = verify_otp_request.email
        otp = verify_otp_request.otp

        user = self.db.query(Users).filter(Users.email == email).first()

        if not user:
            raise UserNotFoundError()

        if user.is_verified:
            raise UserAlreadyVerifiedError()

        otp_key = f"otp:{email}"
        otp_in_redis = await self.redis_client.get(otp_key)

        if not otp_in_redis or otp_in_redis != otp:
            raise InvalidOTPError()

        user.is_verified = True
        self.db.commit()

        # Delete OTP
        await self.redis_client.delete(otp_key)

        access_token = create_token(
            email=user.email,
            user_id=user.id,
            expires_delta=config.access_token_expire_delta,
            type="access",
        )
        refresh_token = create_token(
            email=user.email,
            user_id=user.id,
            expires_delta=config.refresh_token_expire_delta,
            type="refresh",
        )

        await self.redis_client.setex(
            f"refresh_token:{user.id}:{verify_otp_request.device_id}",
            config.refresh_token_expire_delta,
            refresh_token,
        )

        return VerifyOTPResponse(
            access_token=access_token, refresh_token=refresh_token
        )
