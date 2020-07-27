from flask import Flask, json, request, make_response, render_template
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
            cookie = request.cookies          ## commented out for development only

            try:
                csrf_token = request.headers.get('Authorization')
                # token = request.headers.get('token')  ##for dev only
                token = cookie.get('token')
                user_id = content['user_id']
            except Exception as error:
                raise ValueError('{} data is missing in the request'.format(str(error)))

            dataLayer.authenticate_user(user_id, token, csrf_token)

        except Exception as err:
            response = application.response_class(
                response=json.dumps({"authentication failed": 'the following error occurred:' +  str(err)}),
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
                # token = request.headers.get('token')  # for dev only

                cookie = request.cookies          ## commented out for development only
                token = cookie.get('token')
                user_id = content['user_id']

            except Exception as error:
                raise ValueError('{} data is missing in the request'.format(str(error)))

            auth = dataLayer.authenticate_user(user_id, token, csrf_token)
            print(auth)
            if auth['role'] == 'admin':
                return f(*args, **kwargs)
            raise ValueError('Only admins are allowed to access this page')

        except Exception as err:
            return application.response_class(
                response=json.dumps("error " + str(err)),
                status=401,
                mimetype='application/json',

            )
    return decorated

@application.route('/', methods=['POST', 'GET'])
def health_check_aws():

    return 'success', 200, {"Content-Type": "application/json"}


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
            try:
                email = content['email']
                password = content['password']

            except Exception as error:
                raise ValueError('{}, data is missing in the request'.format(str(error)))

            execute_login = dataLayer.log_user(email, password)
            csrf_token = execute_login["csrf_token"]
            user_id = execute_login["_id"]
            token = execute_login["token"]
            role = execute_login["role"]
            first_name = execute_login ["first_name"]
            last_name = execute_login ["last_name"]

            response = application.response_class(
                response=json.dumps({"user_id": user_id, "role": role, "first_name": first_name,
                                     "last_name": last_name}),
                status=200,
                mimetype='application/json',
                headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                         'Access-Control-Allow-Credentials': "true",
                         'Access-Control-Allow-Headers': "Content-Type",
                         # 'Access-Control-Expose-Headers': ["Authorization", "token"], ### dev only
                         'Access-Control-Expose-Headers': "Authorization",
                         "Authorization":  csrf_token,
                         # "token":  token #development only
                         }

            )

            response.set_cookie('token', value=token, httponly=True,
                                domain='keepershomestaging-env.eba-b9pnmwmp.eu-central-1.elasticbeanstalk.com',
                                path='*', expires=datetime.utcnow() + timedelta(minutes=10), secure=True,
                                samesite='none')


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

    response.set_cookie('token', value='new_token', httponly=True,
                        domain='keepershomestaging-env.eba-b9pnmwmp.eu-central-1.elasticbeanstalk.com',
                        path='/', expires=0, secure=True, samesite='none')

    return response


@application.route('/all_users')
def all_users():
    users = dataLayer.all_users()

    all_users_list = []

    for i in users:
        all_users_list.append(i)

    response = application.response_class(response=(json.dumps({"users": all_users_list}, default=str)), status=200,
                                          mimetype="application/json")
    return response


@application.route('/add_user', methods=["POST"])
@admin_required
def add_user():
    try:
        content = request.json
        try:
            added_user = dataLayer.add_user(content)
        except Exception as e:
            raise ValueError('the following error occurred when trying to add a new user: {}'.format(str(e)))

        try:
            email_address = added_user['email']
            user_id = added_user['_id']
            token = added_user['token']
            url = 'http://localhost:3000/resetpassword/path?id=' + user_id + '&token=' + token
            try:
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
        except Exception as error:
            raise ValueError(str(error))

    except Exception as error:
        return json.dumps(error, default=str), 401, {"Content-Type": "application/json"}


@application.route('/delete_user/<string:user_id>', methods=["DELETE"])
def delete_user(user_id):
    deleted_user = dataLayer.delete_user(user_id)
    resp = json.dumps(deleted_user, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/make_admin/<string:user_id>', methods=["POST"])
def make_admin(user_id):
    new_admin = dataLayer.make_admin(user_id)
    resp = json.dumps(new_admin, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/demote_admin/<string:user_id>', methods=["POST"])
def demote_admin(user_id):
    demoted_admin = dataLayer.demote_admin(user_id)
    resp = json.dumps(demoted_admin, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_first_name/<string:user_id>', methods=["POST"])
def change_first_name(user_id):
    changed_name = dataLayer.change_first_name(user_id)
    resp = json.dumps(changed_name, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_last_name/<string:user_id>', methods=["POST"])
def change_last_name(user_id):
    changed_name = dataLayer.change_last_name(user_id)
    resp = json.dumps(changed_name, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_email/<string:user_id>', methods=["POST"])
def change_email(user_id):
    changed_email = dataLayer.change_email(user_id)
    resp = json.dumps(changed_email, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_user_id/<string:user_id>', methods=["POST"])
def change_user_id(user_id):
    changed_user_id = dataLayer.change_user_id(user_id)
    resp = json.dumps(changed_user_id, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_password/<string:user_id>', methods=["POST"])
def change_password(user_id):
    changed_password = dataLayer.change_password(user_id)
    resp = json.dumps(changed_password, default=str), 200, {"Content-Type": "application/json"}
    return resp


def _build_cors_preflight_response():

    response = application.response_class(

        status=200,
        mimetype='application/json',
        headers={'Access-Control-Allow-Origin': "http://localhost:3000", 'Access-Control-Allow-Credentials': "true",
                 'Access-Control-Allow-Headers': "Content-Type"}

    )

    return response



if __name__ == "__main__":
    port = os.environ.get('PORT')
    if port:
        application.run(host='0.0.0.0', port=int(port))
    else:
        application.run(debug=True)
