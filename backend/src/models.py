from sqlalchemy import Boolean, String, Column, ForeignKey, JSON, INT
from sqlalchemy.orm import Mapped, mapped_column

from src.database import Base


class Users(Base):

    __tablename__ = "Users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    first_name: Mapped[str] = mapped_column(String)
    email: Mapped[str] = mapped_column(String, unique=True)
    hashed_password: Mapped[str] = mapped_column(String)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)


class UserEmailAccount(Base):
    __tablename__ = "email_accounts"

    id = Column(String, primary_key=True)
    user_id = Column(INT, ForeignKey("Users.id"))
    email = Column(String, unique=True)
    provider = Column(String)  # 'gmail', 'outlook', etc.
    credentials = Column(JSON)  # Encrypted tokens
