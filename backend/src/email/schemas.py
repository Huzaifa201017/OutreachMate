from pydantic import BaseModel, EmailStr


class OAuthInitResponse(BaseModel):
    auth_url: str
    state: str
    message: str


class OAuthCallbackResponse(BaseModel):
    message: str
    email: str
    account_id: str


class SendEmailRequest(BaseModel):
    account_id: str
    to_email: EmailStr
    subject: str
    body: str
    display_name: str
