from flask import Flask, json, request, render_template
import pymongo
from flask_cors import CORS
import os
from db.Data_Layer import DataLayer
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
from flask_mail import Mail, Message

mail_settings = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": os.getenv('EMAIL'),
    "MAIL_PASSWORD": os.getenv('EMAIL_PASSWORD'),
    "MAIL_DEFAULT_SENDER": ('KeepersHome', os.getenv('EMAIL'))
}

load_dotenv()
application = Flask(__name__)
CORS(application)
CORS(application, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:3000"}})
bcrypt = Bcrypt(application)
__client = pymongo.MongoClient('10.150.54.176:27017', 27017, username=os.getenv("USER_NAME"),
                               password=os.getenv("PASSWORD"))
application.config.update(mail_settings)
mail = Mail(application)
dataLayer = DataLayer(bcrypt, __client)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            content = request.json
            cookie = request.cookies  # commented out for development only

            try:
                csrf_token = request.headers.get('Authorization')
                if csrf_token is None:
                    raise ValueError('csrf')
                # token = request.headers.get('token')  # for dev only
                token = cookie.get('token')
                user_id = content['_id']
            except Exception as error:
                raise ValueError('{} data is missing in the request'.format(str(error)))

            dataLayer.authenticate_user(user_id, token, csrf_token)

        except Exception as err:
            if str(err) == 'Signature expired':

                response = application.response_class(
                    response=json.dumps("signature expired"),
                    status=403,
                    mimetype='application/json',

                )
                return response
            response = application.response_class(
                response=json.dumps("authentication failed:" + str(err)),
                status=401,
                mimetype='application/json',

            )
            return response

        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            try:
                content = request.json
                csrf_token = request.headers.get('Authorization')

                cookie = request.cookies  # commented out for development only
                token = cookie.get('token')
                user_id = content['_id']

            except Exception as error:
                raise ValueError('{} data is missing in the request'.format(str(error)))

            dataLayer.authenticate_user(user_id, token, csrf_token)

        except Exception as err:
            if str(err) == 'Signature expired':

                response = application.response_class(
                    response=json.dumps("authentication failed:" + str(err)),
                    status=403,
                    mimetype='application/json',
                )
                return response

            response = application.response_class(
                response=json.dumps("authentication failed:" + str(err)),
                status=401,
                mimetype='application/json',
            )
            return response
        return f(*args, **kwargs)
    return decorated


def refresh_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            content = request.json
            cookie = request.cookies  # commented out for development only

            try:
                # ref_token = request.headers.get('refresh_token')  ##for dev only
                ref_token = cookie.get('refresh_token')
                user_id = content['_id']
            except Exception as error:
                raise ValueError('{} data is missing in the request'.format(str(error)))

            authenticated_user = dataLayer.authenticate_refresh_token(user_id, ref_token)

        except Exception as err:
            response = application.response_class(
                response=json.dumps("authentication failed:" + str(err)),
                status=401,
                mimetype='application/json',
            )

            return response

        return f(authenticated_user, *args, **kwargs)

    return decorated


@application.route('/', methods=['POST', 'GET'])
def health_check_aws():
    return 'success', 200, {"Content-Type": "application/json"}


@application.route('/refresh_token', methods=['POST', 'GET'])
@refresh_token_required
def refresh_token(user_dic):
    try:
        fresh_tokens = dataLayer.refresh_token(user_dic)
        token = fresh_tokens['access_token']
        refresh_token = fresh_tokens['refresh_token']

        response = application.response_class(
            response=json.dumps('authorized'),
            status=200,
            mimetype='application/json',
            headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                     'Access-Control-Allow-Credentials': "true",
                     'Access-Control-Allow-Headers': ["Content-Type", "Authorization"],
                     'Access-Control-Expose-Headers': ["Authorization"],
                     }

        )

        response.set_cookie('token', value=token, httponly=True,
                            domain='keepershomestaging-env.eba-b9pnmwmp.eu-central-1.elasticbeanstalk.com',
                            path='*', expires=datetime.utcnow() + timedelta(minutes=10), secure=True,
                            samesite='none')
        response.set_cookie('refresh_token', value=refresh_token, httponly=True,
                            domain='keepershomestaging-env.eba-b9pnmwmp.eu-central-1.elasticbeanstalk.com',
                            path='*', expires=datetime.utcnow() + timedelta(minutes=10), secure=True,
                            samesite='none')

        return response

    except Exception as error:
        return json.dumps(error, default=str), 401, {"Content-Type": "application/json"}


@application.route('/test', methods=['POST', 'GET'])
@token_required
# @admin_required
def test_route():

    return 'HELLO KEEPER HOME', 200, {'Access-Control-Allow-Origin': "http://localhost:3000",
                                      'Access-Control-Allow-Credentials': "true",
                                      'Access-Control-Allow-Headers': ["Content-Type", "Authorization"]
                                      }


@application.route('/login', methods=['POST', 'OPTIONS'])
def log_in():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()
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
                keys = ['_id', 'role', "first_name", "last_name" ]
                new_dic = {key: execute_login[key] for key in keys}
                response = application.response_class(
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
                    solicit_new_pass()
                    raise ValueError('too many failed attempts, a password reset has been sent to your email.')
                elif failed_email["attempts"] >= 10:
                    if failed_email["attempts"] % 5:
                        dataLayer.block_current_password(email)
                        raise Exception("user is blocked. Turn to your admin")
                    raise Exception("user is blocked")
                else:
                    raise ValueError('password is incorrect')

        except Exception as error:
            return json.dumps(error, default=str), 401, {"Content-Type": "application/json"}


@application.route('/check_token', methods=['GET', 'POST', 'OPTIONS'])
def check_token_for_pass_reset():
    if request.method == "OPTIONS":
        return _build_cors_preflight_response()

    elif request.method == "POST":
        try:
            try:
                content = request.json
                token = request.headers.get('token')
                user_id = content['_id']
            except Exception as error:
                raise Exception('{} data is missing in the request'.format(str(error)))

            dataLayer.authenticate_user(user_id, token)
            response = application.response_class(
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


@application.route('/logout', methods=['GET', 'POST'])
def logout():
    response = application.response_class(
        response='logout',
        status=200,
        mimetype='application/json',
        headers={'Access-Control-Allow-Origin': "http://localhost:3000"}

    )

    return response


@application.route('/all_users', methods=['GET', 'POST'])
@admin_required
def all_users():
    try:
        users = dataLayer.all_users()
        all_users_list = []

        for i in users:
            all_users_list.append(i)

        response = application.response_class(response=(json.dumps({"users": all_users_list}, default=str)), status=200,
                                              mimetype="application/json")
        return response

    except Exception as e:
        return json.dumps(e, default=str), 400, {"Content-Type": "application/json"}


@application.route('/add_user', methods=["POST"])
@admin_required
def add_user():
    try:
        content = request.json
        added_user = dataLayer.add_user(content)
        email_address = added_user['email']
        user_id = added_user['_id']
        token = added_user['token']
        sent_mail = send_password_by_mail(email_address, user_id, token)

        return sent_mail

    except Exception as error:
        return json.dumps(error, default=str), 400, {"Content-Type": "application/json"}


@application.route('/newpass_solicit', methods=['GET', 'POST'])
def solicit_new_pass():
    try:
        try:
            email = request.json['email']

        except Exception as error:
            raise ValueError('{} data is missing in the request'.format(str(error)))
        user_dic = dataLayer.solicit_new_password(email)
        if user_dic is None:
            raise ValueError('user does not exist in db')

        token = user_dic['token']
        user_id = user_dic['_id']
        sent_email = send_password_by_mail(email, user_id, token)

        return sent_email

    except Exception as error:
        return json.dumps(error, default=str), 401, {"Content-Type": "application/json"}


@application.route('/delete_user', methods=["DELETE"])
@admin_required
def delete_user():
    try:
        content = request.json
        _id = content['user_id']  # must stay user_id!
        deleted_user = dataLayer.delete_user(_id)
        resp = json.dumps(deleted_user, default=str), 200, {"Content-Type": "application/json"}
        return resp
    except Exception as e:
        return json.dumps('Delete failed: {}'.format(e), default=str), 401, {"Content-Type": "application/json"}


@application.route('/make_admin/<string:_id>', methods=["POST"])
def make_admin(_id):
    new_admin = dataLayer.make_admin(_id)
    resp = json.dumps(new_admin, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/demote_admin/<string:_id>', methods=["POST"])
def demote_admin(_id):
    demoted_admin = dataLayer.demote_admin(_id)
    resp = json.dumps(demoted_admin, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_first_name/<string:_id>', methods=["POST"])
def change_first_name(_id):
    changed_name = dataLayer.change_first_name(_id)
    resp = json.dumps(changed_name, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_last_name/<string:_id>', methods=["POST"])
def change_last_name(_id):
    changed_name = dataLayer.change_last_name(_id)
    resp = json.dumps(changed_name, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_email/<string:_id>', methods=["POST"])
def change_email(_id):
    changed_email = dataLayer.change_email(_id)
    resp = json.dumps(changed_email, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_id/<string:_id>', methods=["POST"])
def change_id(_id):
    changed_id = dataLayer.change_id(_id)
    resp = json.dumps(changed_id, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_password', methods=["POST"])
def change_password():
    try:
        content = request.json
        changed_password = dataLayer.change_password(content)

        response = application.response_class(response=json.dumps("Password has been changed successfully:" +
                                                                  changed_password),
                                              status=200,
                                              mimetype='application/json',
                                              headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                                                       'Access-Control-Allow-Credentials': "true",
                                                       'Access-Control-Allow-Headers': ["Content-Type"]}
                                              )
        return response
    except Exception as err:
        response = application.response_class(response=json.dumps("update failed:" + str(err)),
                                              status=401,
                                              mimetype='application/json')
        return response


def _build_cors_preflight_response():
    response = application.response_class(
        status=200,
        mimetype='application/json',
        headers={'Access-Control-Allow-Origin': "http://localhost:3000", 'Access-Control-Allow-Credentials': "true",
                 'Access-Control-Allow-Headers': ["Content-Type", "token"]}

    )
    return response


def send_password_by_mail(email_address, user_id, token):
    try:
        url = 'http://localhost:3000/change_pass/path?id=' + user_id + '&token=' + token

        msg = Message('Reset Password', recipients=[email_address])
        msg.body = render_template('reset_password.txt', url=url)
        msg.html = render_template('reset_pass.html', title='reset password',
                                   url=url)
        mail.send(msg)
    except Exception as error:
        raise ValueError("failed to send email {}".format(str(error)))

    resp = application.response_class(
        response=json.dumps({"message": "email to the new user has been sent successfully",
                             "user_id": user_id}),
        status=200,
        mimetype='application/json',
        headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                 'Access-Control-Allow-Credentials': "true",
                 'Access-Control-Allow-Headers': "Content-Type",
                 }
    )
    return resp


if __name__ == "__main__":
    port = os.environ.get('PORT')
    if port:
        application.run(host='0.0.0.0', port=int(port))
    else:
        application.run(debug=True)
