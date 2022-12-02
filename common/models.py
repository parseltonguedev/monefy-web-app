"""Application models"""
from typing import Any

from sqlalchemy import INTEGER, Column, String
from sqlalchemy.orm import declarative_base

Base: Any = declarative_base()


class BaseModel(Base):
    """Base model for application tables"""

    __abstract__ = True
    id = Column(INTEGER(), primary_key=True)


class User(BaseModel):
    """User table model"""

    __tablename__ = "users"
    uuid = Column(String)
    username = Column(String)
    photo = Column(String)
    account_id = Column(String)
    access_token = Column(String)

    def to_dict(self) -> dict[str, Any]:
        """Dictionary representation of User model"""

        return {"uuid": self.uuid, "username": self.username, "photo": self.photo}
