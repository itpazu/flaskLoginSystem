from app.login import bp
from app.decorators import Decorators
from flask import request, abort
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
        return response.error_response({"message": "authentication failed", 'status_code': 401,
                                     'log': 'token for user %s could not be issued. Reason: %(reason)s'
                                            %(user_dic['_id'], str(error))}, request.path)


@bp.route('/test', methods=['POST', 'GET'])
@decorators.token_required
# @decorators.admin_required
def test_route():

    return 200, 'success'
    # raise ClientError('log this to log file', request.path , status_code=410, message='show this to client')



@bp.route('/login', methods=['POST', 'OPTIONS'])
def log_in():
    if request.method == "OPTIONS":
        return response.build_cors_preflight_response()
    elif request.method == "POST":
        try:
            content = request.json
            # ip_address = request.remote_addr

            try:
                email = content['email']
                password = content['password']

            except Exception as error:
                raise Exception('%s data is missing in the request' % str(error))

            execute_login = dataLayer.log_user(email, password)

            if execute_login:
                # dataLayer.delete_ip_attempts(ip_address)
                dataLayer.delete_email_attempts(email)
                keys = execute_login.keys()
                new_dic = {key: execute_login[key] for key in keys if key != "token" and key != "refresh_token" and
                           key != "csrf_token"}
                return response.response_with_token(new_dic, execute_login["token"], execute_login["refresh_token"],
                                                    execute_login["csrf_token"])

            else:
                default_message = 'login failed check your credentials. A password reset might have been sent to' \
                                  'your account, or issue a password reset request now. Alternatively, turn to your admin'
                failed_email = dataLayer.log_attempt(email)
                if failed_email["attempts"] == 5:
                    dataLayer.block_current_password(email)
                    user_dic = dataLayer.solicit_new_password(email)
                    token = user_dic['token']
                    user_id = user_dic['_id']
                    try:
                        email_helper.send_password_by_mail(email, user_id, token)
                    except Exception as error:
                        raise Exception(error.args[0])
                    raise Exception({"message": default_message, 'status_code': 401,
                                     'log': " an email was sent to reset password for account %s, "
                                            "due to %d unsuccessful login attempts"
                                            % (email, failed_email['attempts'])})

                elif failed_email["attempts"] == 10:
                    dataLayer.block_current_password(email, True)
                    try:
                        admin_emails = list(dataLayer.get_admins())
                        recipients = [admin.get("email") for admin in admin_emails]
                        email_helper.notify_admins(email, recipients)
                    except Exception as error:
                        response.log_error('failed to notify admins: %s' % (str(error)), request.path)
                        pass
                    raise Exception({"message": default_message, 'status_code': 401,
                                     'log': "%s, account has been blocked due to %d unsuccessful login attempts"
                                            % (email, failed_email['attempts'])})
                elif failed_email["attempts"] > 10 and failed_email["attempts"] % 5 == 0:
                    dataLayer.block_current_password(email)
                    raise Exception({"message": default_message, 'status_code': 401,
                                     'log': "%s, is blocked, password is changed automatically every 5 "
                                            "additional attempts. current count: %d unsuccessful login attempts"
                                            % (email, failed_email['attempts'])})
                else:
                    ## don't provide "log" entry in the dictionary, but provide status code to avoid logging the error!
                    raise Exception({'message': default_message,
                                     'status_code': 401})
        except Exception as error:
            return response.error_response(error, request.path)




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

            return response.generate_response('approved')
        except Exception as error:
            return response.error_response(str(error), request.path)


@bp.route('/change_password', methods=["POST"])
def change_password():
    try:
        content = request.json
        changed_password = dataLayer.change_password(content)

        return response.generate_response("Password has been changed successfully:" + changed_password)

    except Exception as error:
        response.error_response(error, request.path)


@bp.route('/newpass_solicit', methods=['GET', 'POST'])
def solicit_new_pass():
    try:
        try:
            email = request.json['email']
        except Exception as error:
            raise Exception('email is missing in the request')

        user_dic = dataLayer.solicit_new_password(email)
        if user_dic is None:
            raise Exception({"message": "password could not be reset, turn to your admin", 'status_code': 401,
             'log': "user %s does not exist in db" % email})

        token = user_dic['token']
        user_id = user_dic['_id']

        sent_email = email_helper.send_password_by_mail(email, user_id, token)

        return response.response_with_headers(sent_email)

    except Exception as error:
        return response.error_response(error, request.path)

