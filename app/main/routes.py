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

@bp.route('/get_costumer/<str:email>', methods=['GET'])
def get_costumer_by_mail(email):
    try:
        current_status = requests.get("path_to_api/email")
        return response.generate_response(current_status)
    except Exception as error:
        return response.error_response(str(error))

    # path: / admin / fixed - vip / {user_id}?end =

@bp.route('/change_vip_status/<int:user_id>', methods=['UPDATE'])
def change_vip_status(user_id):
    milliseconds = int(time() * 1000)
    change_status = requests.get("stage-api.keeperschildsafety.net/admin/fixed-vip/" + user_id + f'''?end={milliseconds}''')
