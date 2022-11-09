"""Module for additional configuration for application instance"""
import os
from typing import Any, AnyStr, Callable, Dict, Optional, Type

import psycopg2
from cryptography.fernet import Fernet
from sanic import Sanic
from sanic.config import SANIC_PREFIX, Config
from sanic.handlers import ErrorHandler
from sanic.request import Request
from sanic.router import Router
from sanic.signals import SignalRouter

from aggregation_service.aggregation_resources import (
    data_aggregation_bp,
    dropbox_webhook_bp,
)
from common.dropbox_utils import DropboxAuthenticator
from transactions_service.transactions_resources import transactions_bp
from user_interface_service.user_interface_resources import (
    dropbox_authentication_bp,
    healthcheck_bp,
    homepage_bp,
    monefy_expense_bp,
    monefy_income_bp,
    monefy_info_bp,
)


class ApplicationLauncher(Sanic):
    """Application launcher class for additional configuration"""

    secret = os.environ["SECRET"].encode()
    __db_name = os.environ["POSTGRES_DB"]
    __db_user = os.environ["POSTGRES_USER"]
    __db_host = os.environ["POSTGRES_HOST"]
    __db_password = os.environ["POSTGRES_PASSWORD"]

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

    def setup_app_config(self) -> None:
        """Method that adds or edit application configuration variables"""
        self.config.FALLBACK_ERROR_FORMAT = "text"
        self.config.CORS_ORIGINS = (
            "http://localhost:8000",
            "http://localhost:8001",
            "http://localhost:8002"
            if self.config.get("LOCAL")
            else "https://monefied.xyz"
        )
        self.config.ALLOWED_ORIGINS = [
            "http://localhost:8000",
            "http://localhost:8001",
            "http://localhost:8002",
            "https://monefied.xyz",
            "https://www.dropbox.com/",
        ]
        self.config.SECRET = self.secret

    def setup_app_context(self) -> None:
        """Method that attach properties and data to ctx object"""
        self.ctx.dropbox_authenticator = DropboxAuthenticator()
        self.ctx.sqlite_connection = psycopg2.connect(
            f"dbname='{self.__db_name}'"
            f" user='{self.__db_user}'"
            f" host='{self.__db_host}'"
            f" password='{self.__db_password}'"
        )
        self.ctx.token_cryptography = Fernet(self.secret)

        with self.ctx.sqlite_connection as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                uuid TEXT,
                account_id TEXT,
                access_token TEXT,
                username TEXT,
                photo TEXT
            )
                """
                )

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
