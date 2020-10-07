from app.decorators import Decorators
from flask import Blueprint
from app.make_response import ReturnResponse
from app.email import Email



def construct_bp(arg, DataLayer):
    data_layer_student = DataLayer()
    decorators = Decorators()
    response = ReturnResponse()
    email = Email()
    bp = Blueprint(arg, __name__)
    bp.db = data_layer_student
    bp.decorators = decorators
    bp.response = response
    bp.email = email
    return bp

