class TokenVerificationError(Exception):
    """Raised when token verification fails."""


class InvalidTokenPayloadError(Exception):
    """Raised when token payload is missing required fields."""
