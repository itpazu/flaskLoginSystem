from app.login import bp
from app.decorators import Decorators
from flask import json, request, Response
from datetime import datetime, timedelta
from app.db.Data_Layer_auth import DataLayerAuth
from app.email import Email
from app.make_response import generate_response, response_with_headers, response_with_token, build_cors_preflight_response


dataLayer = DataLayerAuth()
decorators = Decorators()
email_helper = Email()

@bp.route('/refresh_token', methods=['POST', 'GET'])
@decorators.refresh_token_required
def refresh_token(user_dic):
    try:
        fresh_tokens = dataLayer.refresh_token(user_dic)
        token = fresh_tokens['access_token']
        fresh_token = fresh_tokens['refresh_token']

        response = response_with_token('authorized')

        response.set_cookie('token', value=token, httponly=True,
                            domain='keepershomestaging-env.eba-b9pnmwmp.eu-central-1.elasticbeanstalk.com',
                            path='*', expires=datetime.utcnow() + timedelta(minutes=10), secure=True,
                            samesite='none')
        response.set_cookie('refresh_token', value=fresh_token, httponly=True,
                            domain='keepershomestaging-env.eba-b9pnmwmp.eu-central-1.elasticbeanstalk.com',
                            path='*', expires=datetime.utcnow() + timedelta(minutes=10), secure=True,
                            samesite='none')

        return response

    except Exception as error:
        return json.dumps(error, default=str), 401, {"Content-Type": "application/json"}


@bp.route('/test', methods=['POST', 'GET'])  # for development- testing tokens
@decorators.token_required
# @admin_required
def test_route():
    return 'HELLO KEEPER HOME', 200, {'Access-Control-Allow-Origin': "http://localhost:3000",
                                      'Access-Control-Allow-Credentials': "true",
                                      'Access-Control-Allow-Headers': ["Content-Type", "Authorization"]
                                      }


@bp.route('/login', methods=['POST', 'OPTIONS'])
def log_in():
    if request.method == "OPTIONS":
        return build_cors_preflight_response()
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
                keys = ["_id", "role", "first_name", "last_name", "email", "photo"]
                new_dic = {key: execute_login[key] for key in keys}
                if new_dic["photo"] != '':
                    new_photo = new_dic["photo"].decode()
                    new_dic["photo"] = new_photo
                response = Response(
                    response=json.dumps(new_dic),
                    status=200,
                    mimetype='application/json',
                    headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                             'Access-Control-Allow-Credentials': "true",
                             'Access-Control-Allow-Headers': ["Content-Type", "Authorization"],
                             'Access-Control-Expose-Headers': ["Authorization"],
                             "Authorization": execute_login["csrf_token"],
                             }
                )

                response.set_cookie('token', value=execute_login["token"], httponly=True,
                                    domain='keepershomestaging-env.eba-b9pnmwmp.eu-central-1.elasticbeanstalk.com',
                                    path='*', expires=datetime.utcnow() + timedelta(minutes=10), secure=True,
                                    samesite='none')
                response.set_cookie('refresh_token', value=execute_login["refresh_token"], httponly=True,
                                    domain='keepershomestaging-env.eba-b9pnmwmp.eu-central-1.elasticbeanstalk.com',
                                    path='*', expires=datetime.utcnow() + timedelta(minutes=10), secure=True,
                                    samesite='none')
                return response

            else:
                failed_email = dataLayer.log_attempt(email)
                if failed_email["attempts"] == 5:
                    dataLayer.block_current_password(email)
                    try:
                        solicit_new_pass()
                    except Exception as error:
                        raise Exception (error)
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
                    raise ValueError('password is incorrect')

        except Exception as error:
            return json.dumps(error, default=str), 401, {"Content-Type": "application/json"}


@bp.route('/check_token', methods=['GET', 'POST', 'OPTIONS'])
def check_token_for_pass_reset():
    if request.method == "OPTIONS":
        return build_cors_preflight_response()

    elif request.method == "POST":
        try:
            try:
                content = request.json
                token = request.headers.get('token')
                user_id = content['_id']
            except Exception as error:
                raise Exception('{} data is missing in the request'.format(str(error)))

            dataLayer.authenticate_user(user_id, token)
            response = Response(
                response=json.dumps('token approved'),
                status=200,
                mimetype='application/json',
                headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                         'Access-Control-Allow-Credentials': "true",
                         'Access-Control-Allow-Headers': "Content-Type",
                         }

            )
            return response

        except Exception as error:
            return json.dumps(error, default=str), 401, {"Content-Type": "application/json"}


@bp.route('/logout', methods=['GET', 'POST'])
def logout():
    response = Response(
        response='logout',
        status=200,
        mimetype='application/json',
        headers={'Access-Control-Allow-Origin': "http://localhost:3000"}

    )

    return response

@bp.route('/change_password', methods=["POST"])
def change_password():
    try:
        content = request.json
        changed_password = dataLayer.change_password(content)

        response = Response(response=json.dumps("Password has been changed successfully:" +
                                                                  changed_password),
                                              status=200,
                                              mimetype='application/json',
                                              headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                                                       'Access-Control-Allow-Credentials': "true",
                                                       'Access-Control-Allow-Headers': ["Content-Type"]}
                                              )
        return response
    except Exception as err:
        response = Response(response=json.dumps("update failed:" + str(err)),
                                              status=401,
                                              mimetype='application/json')
        return response

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

        return response_with_headers(sent_email)

    except Exception as error:
        response = Response(response=json.dumps("update failed:" + str(error)),
                                              status=401,
                                              mimetype='application/json')
        return response

    ## raise excpetion to solve call from another route