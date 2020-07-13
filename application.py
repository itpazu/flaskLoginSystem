from flask import Flask, json
import pymongo
from flask_cors import CORS
import os
from db.Data_Layer import DataLayer
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

load_dotenv()
application = Flask(__name__)
CORS(application)
bcrypt = Bcrypt(application)
__client = pymongo.MongoClient('10.150.54.176:27017', 27017, username=os.getenv("USER_NAME"),
                               password=os.getenv("PASSWORD"))

dataLayer = DataLayer(bcrypt, __client)


@application.route('/')
def say_hello():
    return 'HELLO KEEPER HOME', 200, {"Content-Type": "application/json"}


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
