from app.main import bp
from flask import request
import requests
import time
from datetime import datetime, timedelta

data_layer = bp.db
decorators = bp.decorators
response = bp.response

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

            year_time = datetime.strptime(expiration_time, "%Y-%m-%d") + timedelta(days=365)

        else:
            year_time = datetime.now() + timedelta(days=365)

        end_time = time.mktime(year_time.timetuple()) * 1000
        end= end_time
        url = f""
        payload = {"end": int(end)}
        headers = {"Auth-Token": ""}
        change_status = requests.put(url, params=payload, headers=headers)
        costumer_details = change_status.json()
        if costumer_details is not None:
            return response.generate_response(costumer_details)
        raise Exception(response.error_response("not found", request.path))
    except Exception as error:
        return response.error_response(error, request.path)

@bp.route('/add_student', methods=['GET', 'POST', 'OPTIONS'])
@decorators.token_required
def add_new_student():
    if request.method == "OPTIONS":
        return response.build_cors_preflight_response()
    try:

        try:
            content = request.json
        except Exception as error:
            raise Exception('{} data is missing'.format(error))

        student_obj = data_layer.add_student(content)
        return response.generate_response('user {} has been added successfully'.format(student_obj['_id']))

    except Exception as error:
        return response.error_response(error, request.path)


@bp.route('/students',  methods=['GET'])
@decorators.token_required
def load_students():
    try:
        load = data_layer.all_users('Students')
        return response.generate_response(load)
    except Exception as error:
        return response.error_response(error, request.path)

@bp.route('/capability_edit', methods=['PUT', 'GET'])
@decorators.token_required
def edit_capability():
    try:
        content = request
        store = data_layer. edit_capability(content)
        return response.generate_response(store)
    except Exception as error:
        response.error_response(error, request.path)

@bp.route('/capability_add', methods=['POST', 'GET'])
@decorators.token_required
def add_capability():
    try:
        get_new = data_layer.add_capability(request)
        return response.generate_response(get_new)
    except Exception as error:
        response.error_response(error, request.path)

@bp.route('/delete_skill', methods=['DELETE'])
@decorators.token_required
def delete_capability():
    try:
        content =request.json
        print(content)
        resp = data_layer.delete_student(request)
        return response.generate_response(resp)
    except Exception as error:
        response.error_response(error, request.path)
