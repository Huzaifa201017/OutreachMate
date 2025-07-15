from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column
from src.database import Base


class Users(Base):

    __tablename__ = "Users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    first_name: Mapped[str] = mapped_column(String)
    email: Mapped[str] = mapped_column(String, unique=True)
    hashed_password: Mapped[str] = mapped_column(String)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
