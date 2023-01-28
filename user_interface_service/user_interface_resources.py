"""Routes for Monefy Web Application user interface service"""
from http import HTTPStatus

from sanic import Blueprint
from sanic.request import Request
from sanic.response import HTTPResponse, json, redirect
from sanic.views import HTTPMethodView
from sanic_ext import render

from common.authentication import require_jwt_authentication
from common.services_view import MonefyApplicationView

healthcheck_bp = Blueprint("healthcheck_bp")
homepage_bp = Blueprint("homepage_bp")
dropbox_authentication_bp = Blueprint("dropbox_authentication_bp")
monefy_info_bp = Blueprint("monefy_info_bp")
monefy_expense_bp = Blueprint("monefy_expense_bp")
monefy_income_bp = Blueprint("monefy_income_bp")


class HealthCheck(HTTPMethodView, attach=healthcheck_bp, uri="/healthcheck"):
    """View for Smoke test"""

    @staticmethod
    async def get(request: Request) -> HTTPResponse:
        """Function for smoke test"""
        return json({"message": "Hello world!"})


class HomePageView(MonefyApplicationView, attach=homepage_bp, uri="/"):
    """Home page View"""

    async def get(self, request: Request) -> HTTPResponse:
        """Homepage route for guest and authenticated user"""
        return await self.authenticator.render_homepage_for_user_or_guest(request)

    async def post(self, request: Request) -> HTTPResponse:
        """Post request route for Dropbox authentication process"""
        return redirect("/auth", status=HTTPStatus.TEMPORARY_REDIRECT)


class DropboxAuthentication(
    MonefyApplicationView, attach=dropbox_authentication_bp, uri="/auth"
):
    """View for Dropbox Authentication"""

    async def get(self, request: Request) -> HTTPResponse:
        """Finish dropbox authentication process after redirect"""
        return await self.authenticator.finish_dropbox_authentication_request(request)

    async def post(self, request: Request) -> HTTPResponse:
        """Start Dropbox authentication process after post request"""
        response = self.authenticator.start_dropbox_authentication_request(request)
        return response


class MonefyInfo(MonefyApplicationView, attach=monefy_info_bp, uri="/info"):
    """View for Monefy Web Application"""

    decorators = [require_jwt_authentication]

    async def get(self, request: Request) -> HTTPResponse:
        """Returns JSON formatted monefy transactions from csv files"""
        return await render("info.html")


class MonefyExpenseChart(
    MonefyApplicationView, attach=monefy_expense_bp, uri="/expense"
):
    """View for Monefy Web Application"""

    decorators = [require_jwt_authentication]

    async def get(self, request: Request) -> HTTPResponse:
        """Returns JSON formatted monefy transactions from csv files"""
        return await render("expense_chart.html")


class MonefyIncomeChart(MonefyApplicationView, attach=monefy_income_bp, uri="/income"):
    """View for Monefy Web Application"""

    decorators = [require_jwt_authentication]

    async def get(self, request: Request) -> HTTPResponse:
        """Returns JSON formatted monefy transactions from csv files"""
        return await render("income_chart.html")
