from app.main import bp
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
@decorators.token_required
def get_customer_by_mail(email):
    try:
        headers = {"Auth-Token" : "c95ddcc4-ad89-45a0-bcbe-3c10eb620f640147fa5e-c25d-4b65-abf1-071820fb1270"}
        url = "https://stage-api.keeperschildsafety.net/admin/user-by-email/?email={}".format(email)
        current_status = requests.get(url,
                                      headers=headers)
        msg = current_status.json()
        return response.generate_response(msg)
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



