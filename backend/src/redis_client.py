from fastapi import FastAPI
import redis.asyncio as redis
from src.config import AppConfig


async def start_redis(app: FastAPI, app_config: AppConfig):
    app.state.redis = await redis.Redis(
        host=app_config.REDIS_HOST,
        port=app_config.REDIS_PORT,
        db=0,
        decode_responses=True,
    )


async def close_redis(app: FastAPI):
    await app.state.redis.close()
