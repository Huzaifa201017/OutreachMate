from pydantic import BaseModel, EmailStr, Field


class UserOut(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True


class CreateUserRequest(BaseModel):
    firstname: str = Field(..., min_length=2, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=64)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str


class RefreshTokenResponse(BaseModel):
    access_token: str
