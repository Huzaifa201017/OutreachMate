import base64
import json
import logging
from typing import Annotated

from fastapi import APIRouter, Request, Response
from fastapi.params import Depends
from sqlalchemy.orm import Session
from src.database import get_db
from src.email.dependencies import get_email_service
from src.email.service import EmailService
from src.models import UserEmailAccount

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/webhooks", tags=["push-notifications"])


@router.post("/gmail-push")
async def handle_gmail_push_notification(
    request: Request,
    email_service: Annotated[EmailService, Depends(get_email_service)],
):
    """Handle Gmail push notifications for reply detection"""
    try:
        await email_service.handle_gmail_push_notification(request)
        return Response(
            status_code=200
        )  # Acknowledge receipt of the notification

    except Exception as e:
        logger.exception("Failed to process Gmail push notification")
        return Response(
            status_code=200
        )  # Always return 200 to prevent retries
