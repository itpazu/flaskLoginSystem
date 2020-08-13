from flask import Flask
from config import Config
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_cors import CORS
import os
from dotenv import load_dotenv
from flask_pymongo import PyMongo

load_dotenv()
bcrypt = Bcrypt()
mail = Mail()
client = PyMongo()

def create_app(config_class=Config):
    application = Flask(__name__)
    application.config.from_object(config_class)
    print(application.config)
    bcrypt.init_app(application)
    mail.init_app(application)
    # client.init_app(application)
    client.init_app(application, connect=True, authSource="admin", username=os.getenv('DB_USER_NAME'), password=os.getenv('DB_PASSWORD'))
    # print(client.db)
    CORS(application)
    CORS(application, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:3000"}})

    from app.main import bp as main_bp
    application.register_blueprint(main_bp)

    from app.login import bp as login_bp
    application.register_blueprint(login_bp)

    return application

# from app.main import routes
# from app.db import Data_Layer
# # from app.db import Data_Layer_auth
# from app.decorators import Decorators