from flask import Flask
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_cors import CORS
import os
from flask_pymongo import PyMongo
from config import Config
# import boto3


# load_dotenv()
bcrypt = Bcrypt()
mail = Mail()
client = PyMongo()

def create_app(config_class= Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    bcrypt.init_app(app)
    mail.init_app(app)
    if app.config['ENV'] == 'development':

        client.init_app(app, connect=True, authSource="admin", username=os.getenv('DB_USER_NAME'),
                        password=os.getenv('DB_PASSWORD'))
    else:
        client.init_app(app, connect=True, authSource="admin", username='keeperHomeTester',
                        password='flasktests12345')

    CORS(app, supports_credentials=True, resources={r"/*":
                                                        {"origins":  ["http://keepershomeclient.s3-website.eu-central-1.amazonaws.com", "http://localhost:3000"]}})

    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    from app.login import bp as login_bp
    app.register_blueprint(login_bp)

    from app.admin import bp as admin_bp
    app.register_blueprint(admin_bp)

    from app.users_profile import bp as profile_bp
    app.register_blueprint(profile_bp)

    return app
