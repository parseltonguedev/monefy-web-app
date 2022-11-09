"""Common utilities for application"""
import json
import os
from decimal import Decimal
from typing import Any

from sanic import Sanic


def get_monefied_app() -> Sanic:
    """Get sanic monefy application instance"""
    service_name = os.environ.get("SERVICE_NAME")
    return Sanic.get_app(service_name)


class DecimalEncoder(json.JSONEncoder):
    """Decimal encoder class for JSON serialization"""

    def default(self, o: Any) -> json.JSONEncoder | str:

        if isinstance(o, Decimal):
            return str(o)

        return json.JSONEncoder.default(self, o)
