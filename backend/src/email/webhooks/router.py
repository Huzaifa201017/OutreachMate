import logging
from typing import Annotated

from fastapi import APIRouter, Request, Response
from fastapi.params import Depends
from sqlalchemy.orm import Session
from src.database import get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["push-notifications"])


@router.post("/gmail-push")
async def handle_gmail_push_notification(
    request: Request, db: Annotated[Session, Depends(get_db)]
):
    logger.info("Received Gmail push notification")
    return Response(status_code=200)
