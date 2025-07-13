from typing import Optional
from pydantic import BaseModel, EmailStr, Field


# Base schemas
class TokenResponse(BaseModel):
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None


class UserCredentials(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=64)


# Request schemas
class CreateUserRequest(UserCredentials):
    firstname: str = Field(..., min_length=2, max_length=50)


class LoginRequest(UserCredentials):
    device_id: str


class RefreshTokenRequest(BaseModel):
    device_id: str


class VerifyOTPRequest(BaseModel):
    otp: str = Field(..., min_length=6, max_length=6)
    email: EmailStr
    device_id: str


# Response schemas
class LoginResponse(TokenResponse):
    requires_verification: bool = False
    detail: Optional[str] = None


class RefreshTokenResponse(TokenResponse):
    access_token: str
    refresh_token: str


class VerifyOTPResponse(TokenResponse):
    access_token: str
    refresh_token: str
