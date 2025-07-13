class AuthConstants:
    """
    This class contains constants used in the authentication module.
    """

    OTP_EMAIL_TEMPLATE: str = "otp-email.html"
    OTP_EMAIL_SUBJECT: str = "OTP Verification Code"
    LOGIN_URL: str = "/auth/login"
    ACCESS_TOKEN_TYPE: str = "access"
    REFRESH_TOKEN_TYPE: str = "refresh"
