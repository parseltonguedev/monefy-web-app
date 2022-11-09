"""Routes for Monefy Web App aggregation service"""
import hmac
import os
from hashlib import sha256
from http import HTTPStatus

from sanic import Blueprint
from sanic.exceptions import Forbidden
from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse, file, json, text
from sanic.views import HTTPMethodView

from aggregation_service.data_aggregator import MonefyDataAggregator
from common.authentication import DropboxClient, require_jwt_authentication
from common.http_codes import NotAcceptable
from user_interface_service.user_interface_resources import MonefyApplicationView

data_aggregation_bp = Blueprint("data_aggregation_bp")
dropbox_webhook_bp = Blueprint("dropbox_webhook_bp")


class MonefyDataAggregatorView(
    MonefyApplicationView, attach=data_aggregation_bp, uri="/aggregation"
):
    """View for Monefy Data Aggregation"""

    decorators = [require_jwt_authentication]

    async def get(self, request: Request) -> HTTPResponse:
        """Return Monefy file with spending's in json/csv format"""
        dp_client = self.authenticator.get_user_dropbox_client(request)
        summarize_file = request.args.get("summarized", "").lower() == "true"
        file_format = request.args.get("format", "").lower()

        logger.info(
            f"request data aggregation in "
            f"{file_format} format"
            f"{', summarized' if summarize_file else '.'}"
        )
        data_aggregator = MonefyDataAggregator(dp_client, file_format, summarize_file)
        try:
            result_file_path = data_aggregator.get_result_file_data()
            logger.info(f"--- result file name - {os.path.basename(result_file_path)}")
            return await file(
                result_file_path, filename=os.path.basename(result_file_path)
            )
        except NotAcceptable:
            logger.error(f"{file_format} format is not supported for data aggregation")
            return json(
                {
                    "message": f"Provided format ({file_format}) "
                    f"not supported for data aggregation."
                    f" Acceptable arguments - 'format - csv or json' and 'summarized (optional)'"
                    f" Example: /aggregation?format=FORMAT&summarized=True "
                },
                status=HTTPStatus.NOT_ACCEPTABLE,
            )


class DropboxWebhook(HTTPMethodView, attach=dropbox_webhook_bp, uri="/dropbox-webhook"):
    """View for Dropbox Webhook"""

    @staticmethod
    async def get(request: Request) -> HTTPResponse:
        """Respond to the webhook verification (GET request)
        by echoing back the challenge parameter"""
        logger.info("verify dropbox webhook")
        if webhook_response := request.args.get("challenge"):
            return text(
                webhook_response,
                headers={
                    "Content-Type": "text/plain",
                    "X-Content-Type-Options": "nosniff",
                },
                status=HTTPStatus.OK,
            )
        raise Forbidden("Manual Dropbox Webhook request is forbidden")

    @staticmethod
    async def post(request: Request) -> HTTPResponse:
        """Write csv files stored in Dropbox storage to instance"""
        logger.info(f"write files by dropbox webhook {str(request.body)}")
        # Make sure this is a valid request from Dropbox
        signature = request.headers.get("X-Dropbox-Signature", "InvalidSignature")
        if not hmac.compare_digest(
            signature,
            hmac.new(
                os.environ.get("DROPBOX_APP_SECRET", "").encode(), request.body, sha256
            ).hexdigest(),
        ):
            logger.error("Dropbox webhook validation check failed: Request forbidden")
            raise Forbidden("Request forbidden", status_code=HTTPStatus.FORBIDDEN)
        logger.info(f"webhook post {request.body=}")
        if accounts := request.json.get("list_folder").get("accounts"):
            for account in accounts:
                # We need to respond quickly to the webhook request, so we do the
                # actual work in a separate thread. For more robustness, it's a
                # good idea to add the work to a reliable queue and process the queue
                # in a worker process.
                user_access_token = request.app.ctx.sqlite_cursor.execute(
                    f"""
                                SELECT access_token FROM users
                                WHERE account_id = '{account}'
                                """
                ).fetchone()[0]
                dp_client = DropboxClient(user_access_token)
                data_aggregator = MonefyDataAggregator(dp_client, "csv", True)
                result_file = data_aggregator.get_result_file_data()
                dp_client.upload_summarized_file(result_file)

        return json({"message": "webhook test"})
