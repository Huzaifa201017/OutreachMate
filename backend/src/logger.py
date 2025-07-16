import logging

from src.settings import Settings


def setup_logging(settings: Settings) -> None:
    logging.basicConfig(
        level=settings.log_level_enum,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
