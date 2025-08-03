from pydantic import BaseModel


class OAuthInitResponse(BaseModel):
    auth_url: str
    state: str
    message: str


class OAuthCallbackResponse(BaseModel):
    message: str
    email: str
    account_id: str
