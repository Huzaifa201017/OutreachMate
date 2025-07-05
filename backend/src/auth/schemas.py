from pydantic import BaseModel


class UserOut(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True


class CreateUserRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str


class RefreshTokenResponse(BaseModel):
    access_token: str
