from datetime import timedelta
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
            raise ValueError(
                "Invalid time unit in ACCESS_TOKEN_EXPIRE_DURATION"
            )


class Config(BaseSettings):
    DB_HOST: str
    DB_NAME: str
    DB_USER: str
    DB_PASSWORD: str
    DB_PORT: int = 5432
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_DURATION: str
    REFRESH_TOKEN_EXPIRE_DURATION: str

    @property
    def db_url(self):
        return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    @property
    def access_token_expire_delta(self) -> timedelta:
        return get_timedelta_from_string(self.ACCESS_TOKEN_EXPIRE_DURATION)

    @property
    def refresh_token_expire_delta(self) -> timedelta:
        return get_timedelta_from_string(self.REFRESH_TOKEN_EXPIRE_DURATION)

    class Config:
        env_file = ".env"
