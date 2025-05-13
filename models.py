from sqlalchemy import Column, Integer, String
from database import Base
from enums import UserRole
from sqlalchemy import Enum as SqlEnum



class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(SqlEnum(UserRole), default=UserRole.user)  