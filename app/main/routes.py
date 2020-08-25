from app.main import bp
from flask import request
import requests
import time
from app.make_response import ReturnResponse
from app.decorators import Decorators
from datetime import datetime, timedelta
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
                                      headers=headers).json()
        if current_status:
            current_status['currentStatus'] = current_status.pop('paymentType')
            return response.generate_response(current_status)
    except Exception as error:
        return response.error_response(str(error))


@bp.route('/change_vip_status', methods=['POST', 'OPTIONS'])
@decorators.token_required
def change_vip_status():
    try:
        costumer_id = request.json.get('costumer_id')
        expiration_time = request.json.get('expirationDate')
        if expiration_time is not None:
            expiration_date = expiration_time
            year_time = datetime.strptime(expiration_date, "%Y-%m-%d") + timedelta(days=365)

        else:
            year_time = datetime.now() + timedelta(days=365)

        end_time = time.mktime(year_time.timetuple()) * 1000
        end= end_time
        url = f"https://stage-api.keeperschildsafety.net/admin/fixed-vip/{costumer_id}"
        payload = {"end": int(end)}
        headers = {"Auth-Token": "c95ddcc4-ad89-45a0-bcbe-3c10eb620f640147fa5e-c25d-4b65-abf1-071820fb1270"}
        change_status = requests.put(url, params=payload, headers=headers)
        costumer_details = change_status.json()
        if costumer_details is not None:
            return response.generate_response(costumer_details)
        raise Exception(response.error_response("not found"))
    except Exception as error:
        return response.error_response(str(error))



