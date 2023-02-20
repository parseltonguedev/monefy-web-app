"""Module for frequently used operations with application data"""
import os
from contextvars import ContextVar

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker


class DatabaseWrapper:
    """ORM wrapper to frequently used operations"""

    __db_connection_string = os.environ["DB_CONNECTION_STRING"]

    def __init__(self, service):
        bind = create_async_engine(self.__db_connection_string, echo=True)

        _sessionmaker = sessionmaker(bind, AsyncSession, expire_on_commit=False)
        _base_model_session_ctx = ContextVar("session")
