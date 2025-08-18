from datetime import datetime, timezone
from typing import List

from sqlalchemy import INT, JSON, Boolean, Column, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from src.database import Base


class Users(Base):

    __tablename__ = "Users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    first_name: Mapped[str] = mapped_column(String)
    email: Mapped[str] = mapped_column(String, unique=True)
    hashed_password: Mapped[str] = mapped_column(String)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # One-to-many: one user → many email accounts
    email_accounts: Mapped[List["UserEmailAccount"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class UserEmailAccount(Base):
    __tablename__ = "email_accounts"

    id: Mapped[str] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("Users.id"))
    email: Mapped[str] = mapped_column(String, unique=True)
    provider: Mapped[str] = mapped_column(String)  # 'gmail', 'outlook', etc.
    credentials: Mapped[dict] = mapped_column(JSON)
    is_credentials_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    notification_config: Mapped[dict] = mapped_column(JSON, nullable=True)

    # Many-to-one: each account → one user
    user: Mapped["Users"] = relationship(back_populates="email_accounts")


class SentEmailTracking(Base):
    __tablename__ = "sent_email_tracking"

    id: Mapped[str] = mapped_column(primary_key=True)
    account_id: Mapped[str] = mapped_column(ForeignKey("email_accounts.id"))
    message_id: Mapped[str] = mapped_column(
        String, nullable=False
    )  # Gmail message ID
    thread_id: Mapped[str] = mapped_column(
        String, nullable=False
    )  # Gmail thread ID
    recipient: Mapped[str] = mapped_column(String, nullable=False)
    subject: Mapped[str] = mapped_column(String, nullable=False)
    sent_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.now(timezone.utc)
    )
    is_replied: Mapped[bool] = mapped_column(Boolean, default=False)
    replied_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
