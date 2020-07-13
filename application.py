from flask import Flask, json, request
import pymongo
from flask_cors import CORS
import os
from db.Data_Layer import DataLayer
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from decouple import config
from functools import wraps


load_dotenv()
application = Flask(__name__)
CORS(application)
bcrypt = Bcrypt(application)
__client = pymongo.MongoClient('10.150.54.176:27017', 27017, username=config("USER_NAME"),
                               password=config("PASSWORD"))
dataLayer = DataLayer(bcrypt, __client)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:

            content = request.json
            token = request.headers.get('auth-token')

            try:
                user_id = content['user_id']
            except Exception as error:
                raise ValueError('id is missing!!! ')

            dataLayer.authenticate_user(user_id, token)

        except Exception as err:
            response = application.response_class(
                response=json.dumps({"error": str(err)}),
                status=401,
                mimetype='application/json'
            )
            return response

        return f(*args, **kwargs)

    return decorated


@application.route('/')
@token_required
def say_hello():
    return 'HELLO KEEPER HOME', 200, {"Content-Type": "application/json"}


@application.route('/get_doc/<string:user_name>')
def get_doc(user_name):
    user_dict = dataLayer.get_doc_by_user_name(user_name)
    resp = json.dumps(user_dict, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/login')
def log_in():
    try:
        content = request.json
        user_name = content['username']
        password = content['password']

        execute_login = dataLayer.log_user(user_name, password)
        return json.dumps(execute_login, default=str), 200, {"Content-Type": "application/json"}

    except Exception as error:
        return json.dumps(error, default=str), 401, {"Content-Type": "application/json"}


@application.route('/add_user', methods=["POST"])
def add_user():
    added_user = dataLayer.add_user()
    resp = json.dumps(added_user, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/delete_user/<string:user_name>', methods=["DELETE"])
def delete_user(user_name):
    deleted_user = dataLayer.delete_user(user_name)
    resp = json.dumps(deleted_user, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/make_admin/<string:user_name>', methods=["POST"])
def make_admin(user_name):
    new_admin = dataLayer.make_admin(user_name)
    resp = json.dumps(new_admin, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/demote_admin/<string:user_name>', methods=["POST"])
def demote_admin(user_name):
    demoted_admin = dataLayer.demote_admin(user_name)
    resp = json.dumps(demoted_admin, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_first_name/<string:user_name>', methods=["POST"])
def change_first_name(user_name):
    changed_name = dataLayer.change_first_name(user_name)
    resp = json.dumps(changed_name, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_last_name/<string:user_name>', methods=["POST"])
def change_last_name(user_name):
    changed_name = dataLayer.change_last_name(user_name)
    resp = json.dumps(changed_name, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_email/<string:user_name>', methods=["POST"])
def change_email(user_name):
    changed_email = dataLayer.change_email(user_name)
    resp = json.dumps(changed_email, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_username/<string:email>', methods=["POST"])
def change_username(email):
    changed_username = dataLayer.change_username(email)
    resp = json.dumps(changed_username, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_user_id/<string:user_name>', methods=["POST"])
def change_user_id(user_name):
    changed_user_id = dataLayer.change_user_id(user_name)
    resp = json.dumps(changed_user_id, default=str), 200, {"Content-Type": "application/json"}
    return resp


@application.route('/change_password/<string:user_name>', methods=["POST"])
def change_password(user_name):
    changed_password = dataLayer.change_password(user_name)
    resp = json.dumps(changed_password, default=str), 200, {"Content-Type": "application/json"}
    return resp


if __name__ == "__main__":
    port = os.environ.get('PORT')
    if port:
        application.run(host='0.0.0.0', port=int(port))
    else:
        application.run(debug=True)
