"""Configuration for Sanic Application"""
import logging
import os
from logging import LogRecord

from sanic import Request
from sanic.exceptions import SanicException
from sanic.log import LOGGING_CONFIG_DEFAULTS

LOGGING_CONFIG_CUSTOM = LOGGING_CONFIG_DEFAULTS
LOGGING_FORMAT = (
    "%(asctime)s - (%(name)s)[%(levelname)s][%(host)s]: "
    "%(request_id)s %(request)s %(message)s %(status)d %(byte)d"
)
LOG_FILE_PATH = "logs/monefy_app.log"
LOG_CLASS = "logging.FileHandler"

os.makedirs(name="logs", exist_ok=True)
old_factory = logging.getLogRecordFactory()


def record_factory(*args: str, **kwargs: str) -> LogRecord:
    """Function that return request id for log messages"""
    record = old_factory(*args, **kwargs)
    record.request_id = ""

    try:
        request = Request.get_current()
    except SanicException:
        ...
    else:
        record.request_id = str(request.id)

    return record


logging.setLogRecordFactory(record_factory)

LOGGING_CONFIG_CUSTOM["formatters"]["access"]["format"] = LOGGING_FORMAT

LOGGING_CONFIG_CUSTOM["handlers"]["internalFile"] = {
    "class": LOG_CLASS,
    "formatter": "generic",
    "filename": LOG_FILE_PATH,
}
LOGGING_CONFIG_CUSTOM["handlers"]["accessFile"] = {
    "class": LOG_CLASS,
    "formatter": "access",
    "filename": LOG_FILE_PATH,
}
LOGGING_CONFIG_CUSTOM["handlers"]["errorFile"] = {
    "class": LOG_CLASS,
    "formatter": "generic",
    "filename": LOG_FILE_PATH,
}

LOGGING_CONFIG_CUSTOM["loggers"]["sanic.root"]["handlers"].append("internalFile")
LOGGING_CONFIG_CUSTOM["loggers"]["sanic.error"]["handlers"].append("errorFile")
LOGGING_CONFIG_CUSTOM["loggers"]["sanic.access"]["handlers"].append("accessFile")
