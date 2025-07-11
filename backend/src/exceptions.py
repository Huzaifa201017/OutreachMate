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


class UserAlreadyExistsError(BaseAppException):
    """Raised when a user already exists in the system."""

    def __init__(self, message="User already exists"):
        super().__init__(message, status.HTTP_400_BAD_REQUEST)


class InvalidCredentialsError(BaseAppException):
    """Raised when user credentials are invalid."""

    def __init__(self, message="Invalid username or password"):
        super().__init__(message, status.HTTP_401_UNAUTHORIZED)


class InvalidTokenError(BaseAppException):
    """Raised when token verification fails."""

    def __init__(self, message="Invalid or expired token"):
        super().__init__(message, status.HTTP_401_UNAUTHORIZED)
