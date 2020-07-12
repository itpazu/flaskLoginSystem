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
            user_id = content['user_id']
            token = request.headers.get('auth-token')
            authenticate = dataLayer.authenticate_user(user_id, token)

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

        if not user_name or not password:
            raise ValueError('error: missing information')

        execute_login = dataLayer.log_user(user_name, password)
        return json.dumps(execute_login, default=str), 200, {"Content-Type": "application/json"}

    except Exception as error:
        return json.dumps(error, default=str), 401, {"Content-Type": "application/json"}




if __name__ == "__main__":
    port = os.environ.get('PORT')
    if port:
        application.run(host='0.0.0.0', port=int(port))
    else:
        application.run(debug=True)
