"""Module for HTTP View Classes extension with frequently used tools"""

from sanic.views import HTTPMethodView

from common.authentication import Authenticator


class MonefyApplicationView(HTTPMethodView):
    """HTTP Method View child class with frequently used tools"""

    authenticator = Authenticator()
