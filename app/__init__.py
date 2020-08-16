from flask import Flask
from config import Config
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_cors import CORS
import os
from dotenv import load_dotenv
from flask_pymongo import PyMongo
import boto3

load_dotenv()
bcrypt = Bcrypt()
mail = Mail()
client = PyMongo()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    bcrypt.init_app(app)
    mail.init_app(app)
    client.init_app(app, connect=True, authSource="admin", username=os.getenv('DB_USER_NAME'),
                    password=os.getenv('DB_PASSWORD'))
    CORS(app)
    CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:3000"}})

    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    from app.login import bp as login_bp
    app.register_blueprint(login_bp)

    from app.admin import bp as admin_bp
    app.register_blueprint(admin_bp)

    from app.users_profile import bp as profile_bp
    app.register_blueprint(profile_bp)

    return app
