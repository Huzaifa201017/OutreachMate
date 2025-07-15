import redis.asyncio as redis
from fastapi import FastAPI
from src.settings import Settings


async def start_redis(app: FastAPI, settings: Settings) -> None:
    app.state.redis = await redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=0,
        decode_responses=True,
    )


async def close_redis(app: FastAPI) -> None:
    await app.state.redis.close()
