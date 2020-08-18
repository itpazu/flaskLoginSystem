from app.login import bp
from app.decorators import Decorators
from flask import request
from app.db.Data_Layer_auth import DataLayerAuth
from app.email import Email
from app.make_response import ReturnResponse

dataLayer = DataLayerAuth()
decorators = Decorators()
email_helper = Email()
response = ReturnResponse()


@bp.route('/refresh_token', methods=['POST', 'GET'])
@decorators.refresh_token_required
def refresh_token(user_dic):
    try:
        fresh_tokens = dataLayer.refresh_token(user_dic)
        token = fresh_tokens['access_token']
        fresh_token = fresh_tokens['refresh_token']

        return response.response_with_token('authorized', token, fresh_token)

    except Exception as error:
        return response.error_response(str(error))


@bp.route('/test', methods=['POST', 'GET'])  # for development- testing tokens
# @decorators.token_required
@decorators.admin_required
def test_route():
    return response.generate_response("test succeeded")


@bp.route('/login', methods=['POST', 'OPTIONS'])
def log_in():
    if request.method == "OPTIONS":
        return response.build_cors_preflight_response()
    elif request.method == "POST":
        try:
            content = request.json
            ip_address = request.remote_addr

            try:
                email = content['email']
                password = content['password']

            except Exception as error:
                raise ValueError('{}, data is missing in the request'.format(str(error)))

            execute_login = dataLayer.log_user(email, password)

            if execute_login:
                # dataLayer.delete_ip_attempts(ip_address)
                dataLayer.delete_email_attempts(email)
                keys = ["_id", "role", "first_name", "last_name", "email"]
                new_dic = {key: execute_login[key] for key in keys}

                return response.response_with_token(new_dic, execute_login["token"], execute_login["refresh_token"],
                                                    execute_login["csrf_token"])

            else:
                failed_email = dataLayer.log_attempt(email)
                if failed_email["attempts"] == 5:
                    dataLayer.block_current_password(email)
                    new_pass = solicit_new_pass()
                    if new_pass.status == 401:
                        raise Exception(new_pass.response)
                    else:
                        raise Exception('too many failed attempts, a password reset has been sent to your email.')
                elif failed_email["attempts"] == 10:
                    dataLayer.block_current_password(email, True)
                    try:
                        admin_emails = list(dataLayer.get_admins())
                        recipients = [admin.get("email") for admin in admin_emails]
                        email_helper.notify_admins(email, recipients)
                    except Exception as error:
                        raise Exception(str(error))
                    raise Exception("user is blocked")
                elif failed_email["attempts"] > 10 and failed_email["attempts"] % 5:
                    dataLayer.block_current_password(email)
                    raise Exception("user is blocked. Turn to your main")
                else:
                    raise Exception('password is incorrect')

        except Exception as error:
            return response.error_response(str(error))


@bp.route('/check_token', methods=['GET', 'POST', 'OPTIONS'])
def check_token_for_pass_reset():
    if request.method == "OPTIONS":
        return response.build_cors_preflight_response()
    elif request.method == "POST":
        try:
            try:
                content = request.json
                token = request.headers.get('token')
                user_id = content['_id']
            except Exception as error:
                raise Exception('{} data is missing in the request'.format(str(error)))

            dataLayer.authenticate_user(user_id, token)

            return response.generate_response('token approved')
        except Exception as error:
            return response.error_response(str(error))


@bp.route('/change_password', methods=["POST"])
def change_password():
    try:
        content = request.json
        changed_password = dataLayer.change_password(content)

        return response.generate_response("Password has been changed successfully:" + changed_password)

    except Exception as error:
        response.error_response(str(error))


@bp.route('/newpass_solicit', methods=['GET', 'POST'])
def solicit_new_pass():
    try:

        email = request.json['email']
        if email is None:
            raise Exception('{} data is missing in the request')
        user_dic = dataLayer.solicit_new_password(email)
        if user_dic is None:
            raise Exception('user does not exist in db')

        token = user_dic['token']
        user_id = user_dic['_id']
        sent_email = email_helper.send_password_by_mail(email, user_id, token)

        return response.response_with_headers(sent_email)

    except Exception as error:
        response.error_response(str(error))
