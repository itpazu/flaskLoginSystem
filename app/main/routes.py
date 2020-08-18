from app.main import bp
from flask import request
import requests
from app.make_response import ReturnResponse
from app.decorators import Decorators
from time import time
decorators = Decorators()
response = ReturnResponse()

@bp.route('/', methods=['POST', 'GET'])
def health_check_aws():
    return 'success', 200, {"Content-Type": "application/json"}

@bp.route('/get_customer/<string:email>', methods=['GET'])
def get_customer_by_mail(email):
    try:
        current_status = requests.get("path_to_api/" + f"{email}")
        return response.generate_response(current_status)
    except Exception as error:
        return response.error_response(str(error))


@bp.route('/change_vip_status/<int:user_id>', methods=['UPDATE'])
def change_vip_status(user_id):
    try:
        url= "stage-api.keeperschildsafety.net/admin/fixed-vip/" + user_id
        milliseconds = int(time() * 1000)
        payload = {"end": milliseconds}
        headers = {"String Auth-Token": ""}
        change_status = requests.put(url, params=payload, headers=headers)
        costumer_details = change_status.json()
        if costumer_details is not None:
            return response.generate_response(costumer_details)
        raise Exception(response.error_response("not found"))
    except Exception as error:
        response.error_response(str(error))



