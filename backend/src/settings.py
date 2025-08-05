import logging
from datetime import timedelta

from pydantic import DirectoryPath, SecretStr
from pydantic_settings import BaseSettings


def get_timedelta_from_string(duration: str) -> timedelta:
    """
    Converts a duration string (e.g., '2m', '1h', '1d') into a timedelta object.
    """
    unit = duration[-1]
    value = int(duration[:-1])

    match unit:
        case "s":
            return timedelta(seconds=value)
        case "m":
            return timedelta(minutes=value)
        case "h":
            return timedelta(hours=value)
        case "d":
            return timedelta(days=value)
        case _:
            raise ValueError("Invalid time unit")


class Settings(BaseSettings):
    DB_HOST: str
    DB_NAME: str
    DB_USER: str
    DB_PASSWORD: str
    DB_PORT: int = 5432
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_DURATION: str
    REFRESH_TOKEN_EXPIRE_DURATION: str
    OTP_EXPIRY: str
    LOG_LEVEL: str = "INFO"
    REDIRECT_URI: str
    GOOGLE_CLIENT_SECRET_FILE: str
    OAUTH2_STATE_EXPIRY: str
    GMAIL_PUBSUB_TOPIC: str

    # Mail
    MAIL_USERNAME: str
    MAIL_PASSWORD: SecretStr
    MAIL_FROM: str
    MAIL_FROM_NAME: str
    MAIL_SERVER: str
    MAIL_PORT: int
    MAIL_STARTTLS: bool
    MAIL_SSL_TLS: bool
    USE_CREDENTIALS: bool
    VALIDATE_CERTS: bool
    TEMPLATE_FOLDER: DirectoryPath
    MAIL_DEBUG: int

    # Redis
    REDIS_HOST: str
    REDIS_PORT: int

    @property
    def db_url(self):
        return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    @property
    def access_token_expire_delta(self) -> timedelta:
        return get_timedelta_from_string(self.ACCESS_TOKEN_EXPIRE_DURATION)

    @property
    def refresh_token_expire_delta(self) -> timedelta:
        return get_timedelta_from_string(self.REFRESH_TOKEN_EXPIRE_DURATION)

    @property
    def otp_expire_delta(self) -> timedelta:
        return get_timedelta_from_string(self.OTP_EXPIRY)

    @property
    def log_level_enum(self) -> int:
        """
        Returns the logging level as an integer enum, e.g., logging.DEBUG, logging.INFO etc.
        Falls back to logging.INFO if the value is invalid.
        """
        return getattr(logging, self.LOG_LEVEL.upper(), logging.INFO)

    @property
    def otp_expiry_description(self) -> str:
        """
        Returns a human-readable description of the OTP expiry duration.
        E.g., "2m" → "2 minutes", "1h" → "1 hour"
        """

        unit_map = {
            "m": ("minute", "minutes"),
            "h": ("hour", "hours"),
            "d": ("day", "days"),
        }

        duration_str = self.OTP_EXPIRY.strip().lower()

        if not duration_str or len(duration_str) < 2:
            raise ValueError(f"Invalid OTP_EXPIRY format: '{duration_str}'")

        num, unit = duration_str[:-1], duration_str[-1]

        if unit not in unit_map:
            raise ValueError(f"Unsupported time unit: '{unit}' in OTP_EXPIRY")

        try:
            value = int(num)
        except ValueError:
            raise ValueError(f"Invalid duration number in OTP_EXPIRY: '{num}'")

        singular, plural = unit_map[unit]
        return f"{value} {singular if value == 1 else plural}"

    @property
    def oauth2_state_expiry_delta(self) -> timedelta:
        return get_timedelta_from_string(self.OAUTH2_STATE_EXPIRY)

    class Config:
        env_file = ".env"
        extra = "ignore"
