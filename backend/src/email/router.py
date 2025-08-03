import logging
from typing import Annotated

from fastapi import APIRouter, Request
from fastapi.params import Depends

from src.auth.dependencies import get_current_user
from src.email.dependencies import get_email_service
from src.email.schemas import (
    OAuthInitResponse,
    OAuthCallbackResponse,
    SendEmailRequest,
)
from src.email.service import EmailService

router = APIRouter(prefix="/email", tags=["email"])
logger = logging.getLogger(__name__)


@router.post("/add-email", response_model=OAuthInitResponse)
async def initiate_gmail_oauth(
    user: Annotated[dict, Depends(get_current_user)],
    email_service: Annotated[EmailService, Depends(get_email_service)],
    provider: str = "gmail",
):
    """Initiate email OAuth flow"""

    result = await email_service.initiate_oauth_flow(user["id"], provider)
    return result


@router.get("/auth/gmail/oauth2callback", response_model=OAuthCallbackResponse)
async def gmail_oauth_callback(
    request: Request,
    email_service: Annotated[EmailService, Depends(get_email_service)],
):
    """Handle Gmail OAuth callback"""
    result = await email_service.handle_oauth_callback(request, "gmail")
    return result


@router.post("/send")
async def send_email(
    request: SendEmailRequest,
    email_service: Annotated[EmailService, Depends(get_email_service)],
    user: Annotated[dict, Depends(get_current_user)],
):
    result = await email_service.send_email(
        user.get("id"),
        request.account_id,
        request.to_email,
        request.subject,
        request.body,
    )
    return result
