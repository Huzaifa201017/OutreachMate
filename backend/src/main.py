import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from src.auth.router import router
from src.dependencies import get_settings
from src.exceptions import BaseAppException
from src.logger import setup_logging
from src.redis_client import close_redis, start_redis

# models.Base.metadata.create_all(bind=engine)

setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    # Code to run on application startup
    logger.info("Initializing Redis ...")
    await start_redis(app, settings)

    yield  # The application will handle requests here

    # Code to run on application shutdown
    logger.info("Closing Redis")
    await close_redis(app)


app = FastAPI(lifespan=lifespan)
app.include_router(router)


# Global exception handler
@app.exception_handler(BaseAppException)
async def app_exception_handler(request, exc) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code, content={"error": exc.message}
    )
