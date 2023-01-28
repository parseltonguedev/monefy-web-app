"""Module for additional configuration for application instance"""
import os
from asyncio import AbstractEventLoop
from contextvars import ContextVar
from typing import Any, AnyStr, Callable, Dict, Optional, Type

from cryptography.fernet import Fernet
from sanic import Sanic
from sanic.config import SANIC_PREFIX, Config
from sanic.handlers import ErrorHandler
from sanic.request import Request
from sanic.response import BaseHTTPResponse
from sanic.router import Router
from sanic.signals import SignalRouter
from sanic.worker.manager import WorkerManager
from sqlalchemy.ext.asyncio import (AsyncEngine, AsyncSession,
                                    create_async_engine)
from sqlalchemy.orm import sessionmaker

from aggregation_service.aggregation_resources import (data_aggregation_bp,
                                                       dropbox_webhook_bp)
from common.dropbox_utils import DropboxAuthenticator
from common.models import Base
from transactions_service.transactions_resources import transactions_bp
from user_interface_service.user_interface_resources import (
    dropbox_authentication_bp, healthcheck_bp, homepage_bp, monefy_expense_bp,
    monefy_income_bp, monefy_info_bp)

WorkerManager.THRESHOLD = 600


class ApplicationLauncher(Sanic):
    """Application launcher class for additional configuration"""

    secret: bytes = os.environ["SECRET"].encode()
    __db_connection_string: str = os.environ["DB_CONNECTION_STRING"]

    def __init__(
        self,
        name: str = "",
        config: Optional[Config] = None,
        ctx: Optional[Any] = None,
        router: Optional[Router] = None,
        signal_router: Optional[SignalRouter] = None,
        error_handler: Optional[ErrorHandler] = None,
        env_prefix: Optional[str] = SANIC_PREFIX,
        request_class: Optional[Type[Request]] = None,
        strict_slashes: bool = False,
        log_config: Optional[Dict[str, Any]] = None,
        configure_logging: bool = True,
        dumps: Optional[Callable[..., AnyStr]] = None,
        loads: Optional[Callable[..., Any]] = None,
        inspector: bool = False,
    ):
        super().__init__(
            name,
            config,
            ctx,
            router,
            signal_router,
            error_handler,
            env_prefix,
            request_class,
            strict_slashes,
            log_config,
            configure_logging,
            dumps,
            loads,
            inspector,
        )
        self.setup_app_config()
        self.setup_app_context()
        self.setup_app_blueprints()
        self.create_db()

    def setup_app_config(self) -> None:
        """Method that adds or edit application configuration variables"""
        self.config.FALLBACK_ERROR_FORMAT = "text"
        self.config.CORS_ORIGINS = (
            "http://localhost:8000",
            "http://localhost:8001",
            "http://localhost:8002"
            if self.config.get("LOCAL")
            else "https://monefied.xyz",
        )
        self.config.ALLOWED_ORIGINS = [
            "http://localhost:8000",
            "http://localhost:8001",
            "http://localhost:8002",
            "https://monefied.xyz",
            "https://www.dropbox.com/",
        ]
        self.config.SECRET = self.secret
        self.config.FORWARDED_SECRET = self.secret.decode()

    def setup_app_context(self) -> None:
        """Method that attach properties and data to ctx object"""
        self.ctx.dropbox_authenticator = DropboxAuthenticator()
        self.ctx.token_cryptography = Fernet(self.secret)

    def setup_app_blueprints(self) -> None:
        """Method that adds existed blueprints to application"""
        user_interface_blueprints = (
            healthcheck_bp,
            homepage_bp,
            dropbox_authentication_bp,
            monefy_info_bp,
            monefy_expense_bp,
            monefy_income_bp,
        )
        transactions_blueprints = (transactions_bp,)
        aggregation_blueprints = (
            data_aggregation_bp,
            dropbox_webhook_bp,
        )

        if self.name == "Monefy-Web-App":
            for service_blueprint in user_interface_blueprints:
                self.blueprint(service_blueprint)
        if self.name == "Transactions-Service":
            for service_blueprint in transactions_blueprints:
                self.blueprint(service_blueprint)
        if self.name == "Aggregation-Service":
            for service_blueprint in aggregation_blueprints:
                self.blueprint(service_blueprint)

    def _create_async_engine(self) -> AsyncEngine:
        return create_async_engine(self.__db_connection_string, echo=True)

    def create_db(self) -> None:
        """Method for configuration application database"""

        engine = self._create_async_engine()

        async def create_tables(app: Sanic, loop: AbstractEventLoop) -> None:

            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)

        self.register_listener(create_tables, "before_server_start")

        async def inject_session(request: Request) -> None:
            request.ctx.session = _sessionmaker()
            request.ctx.session_ctx_token = _base_model_session_ctx.set(
                request.ctx.session
            )

        async def close_session(request: Request, response: BaseHTTPResponse) -> None:
            if hasattr(request.ctx, "session_ctx_token"):
                _base_model_session_ctx.reset(request.ctx.session_ctx_token)
                await request.ctx.session.close()

        _sessionmaker = sessionmaker(engine, AsyncSession, expire_on_commit=False)
        _base_model_session_ctx: ContextVar[str] = ContextVar("session")

        self.register_middleware(inject_session, "request")
        self.register_middleware(close_session, "response")
