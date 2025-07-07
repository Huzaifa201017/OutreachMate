from sqlalchemy import Column, Integer, String
from database import Base


class Users(Base):

    __tablename__ = "Users"
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    email = Column(String, unique=True)
    hashed_password = Column(String)
