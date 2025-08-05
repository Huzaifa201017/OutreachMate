from fastapi import status


class BaseAppException(Exception):
    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
    ):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class UnknowError(BaseAppException):
    def __init__(self, message="Unknown Error"):
        super().__init__(message, status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserAlreadyExistsError(BaseAppException):
    """Raised when a user already exists in the system."""

    def __init__(self, message="User already exists"):
        super().__init__(message, status.HTTP_400_BAD_REQUEST)


class UserNotFoundError(BaseAppException):
    """Raised when a user doesnt exists in the system."""

    def __init__(self, message="User Not Found"):
        super().__init__(message, status.HTTP_400_BAD_REQUEST)


class UserAlreadyVerifiedError(BaseAppException):
    """Raised when a user email is already verified."""

    def __init__(self, message="User Already Verified"):
        super().__init__(message, status.HTTP_400_BAD_REQUEST)


class InvalidCredentialsError(BaseAppException):
    """Raised when user credentials are invalid."""

    def __init__(self, message="Invalid email or password"):
        super().__init__(message, status.HTTP_401_UNAUTHORIZED)


class InvalidTokenError(BaseAppException):
    """Raised when token verification fails."""

    def __init__(self, message="Invalid or expired token"):
        super().__init__(message, status.HTTP_401_UNAUTHORIZED)


class InvalidOTPError(BaseAppException):
    """Raised when the provided OTP is invalid or has expired."""

    def __init__(self, message: str = "Invalid or expired OTP"):
        super().__init__(message, status_code=status.HTTP_401_UNAUTHORIZED)


class InvalidOAuthStateError(BaseAppException):
    """Raised when the provided OAuth state is invalid."""

    def __init__(self, message: str = "Invalid OAuth2 State"):
        super().__init__(message, status_code=status.HTTP_403_FORBIDDEN)


class InvalidOAuthStateException(BaseAppException):
    def __init__(self, state: str | None):
        message = (
            f"Invalid OAuth state: {state}" if state else "Invalid OAuth state"
        )
        super().__init__(message, status.HTTP_400_BAD_REQUEST)


class EmailNotFoundError(BaseAppException):
    def __init__(self):
        super().__init__(
            "Unable to retrieve user email from OAuth provider",
            status.HTTP_400_BAD_REQUEST,
        )


class AccountNotFoundError(BaseAppException):
    def __init__(self, account_id: str):
        super().__init__(
            f"Email account not found: {account_id}", status.HTTP_404_NOT_FOUND
        )


class OAuthInitiationError(BaseAppException):
    def __init__(self, provider: str):
        super().__init__(
            f"Failed to initiate OAuth flow for {provider}",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class OAuthCallbackError(BaseAppException):
    def __init__(self, provider: str):
        super().__init__(
            f"Failed to handle OAuth callback for {provider}",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class EmailSendError(BaseAppException):
    def __init__(self, recipient: str):
        super().__init__(
            f"Failed to send email to {recipient}",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


class CredentialsRefreshError(BaseAppException):
    def __init__(self):
        super().__init__(
            "Failed to refresh OAuth credentials", status.HTTP_401_UNAUTHORIZED
        )
