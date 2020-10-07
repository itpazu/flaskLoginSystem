from app.decorators import Decorators
from flask import Blueprint
from app.make_response import ReturnResponse
from app.email import Email
from functools import wraps



def construct_bp(arg, DataLayer):
    data_layer_student = DataLayer()
    decorators = Decorators()
    response = ReturnResponse()
    email = Email()
    Decorators.admin_required = staticmethod(mock_decorator)
    Decorators.token_required = staticmethod(mock_decorator)
    bp = Blueprint(arg, __name__)
    bp.db = data_layer_student
    bp.decorators = decorators
    bp.response = response
    bp.email = email
    return bp


def mock_decorator(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function

# circumvent the decorators
