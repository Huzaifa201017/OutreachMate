from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from src.exceptions import BaseAppException
from src.logger import setup_logging
import redis.asyncio as redis
from src.auth.router import router

# models.Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):

    # Code to run on application startup
    print("Application is starting up...")
    app.state.redis = redis.Redis(
        host="localhost",
        port=6379,
        db=0,
        decode_responses=True,
    )

    yield  # The application will handle requests here

    # Code to run on application shutdown
    print("Application is shutting down...")
    await app.state.redis.close()


app = FastAPI(lifespan=lifespan)
app.include_router(router)
setup_logging()


# Global exception handler
@app.exception_handler(BaseAppException)
async def app_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code, content={"error": exc.message}
    )
