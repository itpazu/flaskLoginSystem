import os
from dotenv import load_dotenv
from flask_pymongo import PyMongo

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config(object):
    MONGO_URI=os.getenv("MONGO_URI")
    # MONGO_DBNAME = os.getenv('DBNAME')
    # MONGO_HOST = os.getenv('MONGO_HOST')
    # MONGO_PORT = os.getenv('DB_PORT')
    # MONGO_USERNAME = os.getenv('DB_USER_NAME')
    # MONGO_PASSWORD = os.getenv('DB_PASSWORD')
    # MONGO_AUTH_SOURCE='admin'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    MAIL_SERVER= os.getenv('MAIL_SERVER')
    MAIL_USERNAME= os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD=os.getenv('EMAIL_PASSWORD')
    MAIL_PORT=os.getenv('MAIL_PORT')
    MAIL_USE_TLS=False
    MAIL_USE_SSL=True
    MAIL_DEFAULT_SENDER=('KeepersHome', os.getenv('EMAIL'))
