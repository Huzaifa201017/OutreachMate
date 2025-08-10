import logging

from fastapi import BackgroundTasks
from fastapi_mail import ConnectionConfig
from pydantic import EmailStr
from redis.asyncio.client import Redis
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.auth.constants import AuthConstants
from src.exceptions import (
    InvalidCredentialsError,
    InvalidOTPError,
    InvalidTokenError,
    UnknowError,
    UserAlreadyExistsError,
    UserAlreadyVerifiedError,
)
from src.models import Users
from src.settings import Settings
from .schemas import (
    CreateUserRequest,
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    VerifyOTPRequest,
    VerifyOTPResponse,
)
from .utils import (
    create_tokens,
    generate_otp,
    get_cache_value,
    get_password_hash,
    get_user_by_email,
    send_email_with_template,
    set_cache_with_expiry,
    verify_password,
    verify_token,
)

logger = logging.getLogger(__name__)


class AuthService:
    """Service class for authentication operations"""

    def __init__(
        self,
        db: Session,
        redis_client: Redis,
        settings: Settings,
        system_mail_config: ConnectionConfig,
    ):
        self.db = db
        self.redis_client = redis_client
        self.settings = settings
        self.system_mail_config = system_mail_config

    async def _send_otp_email(
        self, recipient_email: EmailStr, recipient_name: str
    ) -> None:
        """
        Send an OTP verification email to a user.

        Flow:
        1. Generate a new OTP
        2. Store OTP in Redis with expiration
        3. Send email with OTP using template

        Args:
            recipient_email: User's email address
            recipient_name: User's first name

        Raises:
            Exception: If OTP generation, storage, or email sending fails
        """

        logger.debug(f"Starting OTP email process for: {recipient_email}")

        try:
            # Step 1: Generate new OTP
            otp = generate_otp()
            logger.info(
                f"Generated OTP for {recipient_email}",
                extra={"user_email": recipient_email},
            )

            # Step 2: Store OTP in Redis
            await set_cache_with_expiry(
                redis_client=self.redis_client,
                key=f"otp:{recipient_email}",
                value=otp,
                expiry_duration=self.settings.otp_expire_delta,
            )
            logger.debug(
                f"Stored OTP in Redis with expiration: {self.settings.otp_expire_delta}s",
                extra={"user_email": recipient_email},
            )

            # Step 3: Prepare and send email
            template_body = {
                "name": recipient_name,
                "otp": otp,
                "company_name": self.settings.MAIL_FROM_NAME,
                "validity_duration_desc": self.settings.otp_expiry_description,
            }

            await send_email_with_template(
                subject=AuthConstants.OTP_EMAIL_SUBJECT,
                recipients=[recipient_email],
                template_name=AuthConstants.OTP_EMAIL_TEMPLATE,
                template_body=template_body,
                mail_config=self.system_mail_config,
            )
            logger.info(
                "OTP email sent successfully",
                extra={
                    "user_email": recipient_email,
                    "template": AuthConstants.OTP_EMAIL_TEMPLATE,
                },
            )

        except Exception as e:
            logger.exception(
                "Failed to send OTP email",
                extra={"user_email": recipient_email},
                exc_info=True,
            )

    def _authenticate_user(self, email: str, password: str) -> Users:
        """
        Authenticates a user by email and password.

        Flow:
        1. Check if user exists with provided email
        2. Validate password against stored hash
        3. Return authenticated user if successful

        Args:
            email: User's email address
            password: User's plaintext password

        Returns:
            Users: Authenticated user model

        Raises:
            InvalidCredentialsError: If email not found or password invalid
        """

        logger.debug("Starting authentication process", extra={"email": email})

        # Step 1: Get User
        user = get_user_by_email(self.db, email)

        # Step 2: Validate password
        if not verify_password(password, user.hashed_password):
            logger.warning(
                "Authentication failed: invalid password",
                extra={"email": email},
            )
            raise InvalidCredentialsError()

        # Step 3: Authentication successful
        logger.info("User authenticated successfully", extra={"email": email})
        return user

    async def create_user(
        self,
        create_user_request: CreateUserRequest,
        background_tasks: BackgroundTasks,
    ) -> None:
        """
        Creates a new user account and initiates email verification.

        Flow:
        1. Hash the user's password
        2. Create new user record in database
        3. Send verification OTP email

        Args:
            create_user_request: Contains user registration details
            background_tasks: FastAPI background tasks handler

        Returns:
            Users: The created user model

        Raises:
            UserAlreadyExistsError: If email already registered
        """

        logger.info(
            "Starting user creation process",
            extra={"email": create_user_request.email},
        )

        try:
            # Step 1: Hash password
            hashed_password = get_password_hash(create_user_request.password)
            logger.debug("Password hashed successfully")

            # Step 2: Create user record
            user = Users(
                first_name=create_user_request.firstname,
                hashed_password=hashed_password,
                email=create_user_request.email,
            )
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)

            logger.info(
                "User created successfully",
                extra={"user_id": user.id, "email": user.email},
            )

            # Step 3: Schedule OTP email
            background_tasks.add_task(
                self._send_otp_email,
                recipient_email=create_user_request.email,
                recipient_name=create_user_request.firstname,
            )
            logger.debug(
                "Verification email scheduled",
                extra={"email": create_user_request.email},
            )

        except IntegrityError as e:
            logger.exception(
                "User creation failed - email already exists",
                extra={"email": create_user_request.email},
            )
            self.db.rollback()
            raise UserAlreadyExistsError() from e

    async def login(
        self,
        login_request: LoginRequest,
        background_tasks: BackgroundTasks,
    ) -> LoginResponse:
        """
        Authenticates user credentials and returns a JWT token if valid.

        Flow:
        1. Authenticate user credentials
        2. Check if user is verified
        3. If not verified, send OTP and return verification required response
        4. If verified, generate tokens and return successful login response
        """

        # Step 1: Authenticate user credentials against database
        user = self._authenticate_user(login_request.email, login_request.password)

        # Step 2: Check if user has verified their email
        if not user.is_verified:
            logger.warning(f"User '{login_request.email}' is not verified.")

            # Step 3a: Send verification OTP via email
            background_tasks.add_task(
                self._send_otp_email,
                recipient_email=user.email,
                recipient_name=user.first_name,
            )

            # Step 3b: Return response indicating verification needed
            return LoginResponse(
                requires_verification=True,
                detail="Email not verified. OTP has been sent to your email.",
            )

        logger.info(f"User '{login_request.email}' verified successfully.")

        # Step 4a: Generate new access and refresh tokens
        access_token, refresh_token = create_tokens(user.email, user.id, self.settings)

        # Step 4b: Store refresh token in Redis for this device, as per device and per email = only one session
        await set_cache_with_expiry(
            redis_client=self.redis_client,
            key=f"refresh_token:{user.id}:{login_request.device_id}",
            value=refresh_token,
            expiry_duration=self.settings.refresh_token_expire_delta,
        )

        logger.info(f"Issued new tokens for user '{user.email}'")

        # Return successful login response with tokens
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
        Refresh access and refresh tokens using a valid refresh token.

        Flow:
        1. Verify the provided refresh token signature and expiry
        2. Extract user information from token payload
        3. Validate token against stored token in Redis to prevent reuse
        4. Generate and store new token pair
        5. Return new tokens to client

        Args:
            refresh_token_request: Contains device_id for token validation
            refresh_token: The refresh token to verify

        Returns:
            RefreshTokenResponse with new access and refresh tokens

        Raises:
            InvalidTokenError: If token is invalid, expired or reused
        """

        logger.debug("Starting token refresh process")

        # Step 1: Verify token signature and expiry
        email, user_id = verify_token(
            refresh_token,
            AuthConstants.REFRESH_TOKEN_TYPE,
            self.settings.SECRET_KEY,
            self.settings.ALGORITHM,
        )

        # Step 3: Validate against stored token
        device_id = refresh_token_request.device_id
        stored_token = await get_cache_value(
            redis_client=self.redis_client,
            key=f"refresh_token:{user_id}:{device_id}",
        )

        if stored_token != refresh_token:
            logger.warning(
                f"Potential token reuse detected - User: {email}, Device: {device_id}"
            )
            raise InvalidTokenError()

        logger.info(f"Valid refresh token for user {email}")

        # Step 4: Generate new tokens
        new_access_token, new_refresh_token = create_tokens(
            email, user_id, self.settings
        )
        await set_cache_with_expiry(
            redis_client=self.redis_client,
            key=f"refresh_token:{user_id}:{device_id}",
            value=new_refresh_token,
            expiry_duration=self.settings.refresh_token_expire_delta,
        )

        logger.info(f"Successfully refreshed tokens for user {email}")

        # Step 5: Return new token pair
        return RefreshTokenResponse(
            access_token=new_access_token, refresh_token=new_refresh_token
        )

    async def verify_otp(
        self, verify_otp_request: VerifyOTPRequest
    ) -> VerifyOTPResponse:
        """
        Verifies the OTP for a user and marks their account as verified.

        Flow:
        1. Validate user exists and needs verification
        2. Check OTP validity against stored value
        3. Mark user as verified
        4. Generate authentication tokens
        5. Return tokens to complete verification

        Args:
            verify_otp_request: Contains email, OTP and device_id

        Returns:
            VerifyOTPResponse with new access and refresh tokens

        Raises:
            UserNotFoundError: If user doesn't exist
            UserAlreadyVerifiedError: If user is already verified
            InvalidOTPError: If OTP is invalid or expired
        """

        logger.info(f"Starting OTP verification for email: {verify_otp_request.email}")

        # Step 1: Validate user exists and needs verification
        user = get_user_by_email(self.db, verify_otp_request.email)

        if user.is_verified:
            logger.warning(f"User already verified: {verify_otp_request.email}")
            raise UserAlreadyVerifiedError()

        # Step 2: Check OTP validity
        otp_key = f"otp:{verify_otp_request.email}"
        stored_otp = await get_cache_value(redis_client=self.redis_client, key=otp_key)

        if not stored_otp or stored_otp != verify_otp_request.otp:
            logger.warning(f"Invalid OTP provided for user: {verify_otp_request.email}")
            raise InvalidOTPError()

        try:
            # Step 3: Mark user as verified
            user.is_verified = True
            self.db.commit()
            self.db.refresh(user)
            logger.info(f"User marked as verified: {verify_otp_request.email}")

            # Clean up the used OTP
            await self.redis_client.delete(otp_key)
            logger.debug(f"OTP deleted from Redis for user: {verify_otp_request.email}")

            # Step 4: Generate authentication tokens
            access_token, refresh_token = create_tokens(
                user.email, user.id, self.settings
            )
            await set_cache_with_expiry(
                redis_client=self.redis_client,
                key=f"refresh_token:{user.id}:{verify_otp_request.device_id}",
                value=refresh_token,
                expiry_duration=self.settings.refresh_token_expire_delta,
            )

            logger.info(
                f"Authentication tokens generated for user: {verify_otp_request.email}"
            )

            # Step 5: Return successful verification response
            return VerifyOTPResponse(
                access_token=access_token, refresh_token=refresh_token
            )

        except Exception as e:
            logger.exception(f"Error during OTP verification: {str(e)}")
            self.db.rollback()
            raise UnknowError() from e
