from sanic.exceptions import SanicException


class NotAcceptable(SanicException):
    """
    **Status**: 406 Not Acceptable
    """

    status_code = 406
    quiet = True
