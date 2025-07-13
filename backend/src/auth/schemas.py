from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class UserOut(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None


class CreateUserRequest(BaseModel):
    firstname: str = Field(..., min_length=2, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=64)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    device_id: str


class RefreshTokenRequest(BaseModel):
    device_id: str


class LoginResponse(TokenResponse):
    requires_verification: bool = False
    detail: Optional[str] = None


class RefreshTokenResponse(TokenResponse):
    access_token: str


class VerifyOTPRequest(BaseModel):
    otp: str
    email: EmailStr
    device_id: str


class VerifyOTPResponse(TokenResponse):
    pass
