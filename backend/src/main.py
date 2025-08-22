import logging
import os
from contextlib import asynccontextmanager

from dotenv import dotenv_values
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from src.auth.router import router as auth_router
from src.dependencies import get_settings
from src.email.router import router as email_router
from src.email.webhooks.router import router as webhook_router
from src.exceptions import BaseAppException
from src.logger import setup_logging
from src.redis_client import close_redis, start_redis

# Load only as a dict
env_vars = dotenv_values(".env")

# Pick only OAuth2 related
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = (
    env_vars["OAUTHLIB_INSECURE_TRANSPORT"] or ""
)

os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = env_vars["OAUTHLIB_RELAX_TOKEN_SCOPE"] or ""


# models.Base.metadata.create_all(bind=engine)

settings = get_settings()
setup_logging(settings)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):

    # Code to run on application startup
    logger.info("Initializing Redis ...")
    await start_redis(app, settings)

    yield  # The application will handle requests here

    # Code to run on application shutdown
    logger.info("Closing Redis")
    await close_redis(app)


app = FastAPI(lifespan=lifespan)
app.include_router(auth_router)
app.include_router(email_router)
app.include_router(webhook_router)


# Global exception handler
@app.exception_handler(BaseAppException)
async def app_exception_handler(request, exc) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.message})
