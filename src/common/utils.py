"""Common utilities for application"""
import json
from decimal import Decimal

from sanic import Sanic


def get_monefied_app() -> Sanic:
    """Get sanic monefy application instance"""
    return Sanic.get_app("Monefy-Web-App")


class DecimalEncoder(json.JSONEncoder):

    def default(self, obj):

        if isinstance(obj, Decimal):
            return str(obj)

        return json.JSONEncoder.default(self, obj)


