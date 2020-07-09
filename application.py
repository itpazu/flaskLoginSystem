from flask import Flask, json
import pymongo
from flask_cors import CORS
import os
from db.Data_Layer import DataLayer
from flask_bcrypt import Bcrypt
from decouple import config
application = Flask(__name__)
CORS(application)
bcrypt = Bcrypt(application)

__client = pymongo.MongoClient('10.150.54.176:27017', 27017, username=os.environ['USER_NAME'], password=os.environ['PASSWORD'])
# __client = pymongo.MongoClient('10.150.54.176:27017', 27017, username=config('USER_NAME'), password=config('PASSWORD'))

dataLayer = DataLayer(bcrypt, __client)

@application.route('/')
def say_hello():
    return 'HELLO KEEPER HOME', 200, {"Content-Type": "application/json"}

@application.route('/get_doc/<string:user_name>')
def get_doc(user_name):
    user_dict = dataLayer.get_doc(user_name)
    resp = json.dumps(user_dict, default=str), 200, {"Content-Type": "application/json"}
    return resp

if __name__ == "__main__":
    port = os.environ.get('PORT')
    if port:
        application.run(host='0.0.0.0', port=int(port))
    else:
        application.run(debug=True)
