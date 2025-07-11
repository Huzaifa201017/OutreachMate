from fastapi import FastAPI
from fastapi.responses import JSONResponse
from auth.router import router
from exceptions import BaseAppException
import models
from database import engine
from logger import setup_logging

setup_logging()

app = FastAPI()

models.Base.metadata.create_all(bind=engine)

app.include_router(router)


# Global exception handler
@app.exception_handler(BaseAppException)
async def app_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code, content={"error": exc.message}
    )


# @app.exception_handler(Exception)
# async def unhandled_exception_handler(request: Request, exc: Exception):
#     # Custom logging for any unexpected error
#     logger.exception(f"Unhandled exception at {request.url.path}: {exc}")

#     return JSONResponse(
#         status_code=500,
#         content={
#             "error": "An unexpected error occurred. Please try again later."
#         },
#     )
