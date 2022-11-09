"""Routes for Monefy Web App transactions service"""
from sanic import Blueprint
from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse, json

from common.authentication import require_jwt_authentication
from common.services_view import MonefyApplicationView

transactions_bp = Blueprint("transactions_bp")


class MonefyInfo(MonefyApplicationView, attach=transactions_bp, uri="/history"):
    """View for Monefy Web Application"""

    decorators = [require_jwt_authentication]

    async def get(self, request: Request) -> HTTPResponse:
        """Returns JSON formatted monefy transactions from csv files"""
        logger.info("getting monefy transactions")
        dp_client = self.authenticator.get_user_dropbox_client(request)
        monefy_stats = dp_client.get_monefy_info()
        return json(body={"monefy_data": monefy_stats})
