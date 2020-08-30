import os
from dotenv import load_dotenv
from config import Config



class ConfigTests(Config):
    MONGO_URI = 'mongodb://keeperHome:a2ce5K5RSvhrzZtx@10.150.54.176:27017/KeeperHomeTests'
    MAIL_DEFAULT_SENDER = ('KeepersHome- tests', os.getenv('EMAIL'))
    ENV = 'testing'
    TESTING = True
    DEBUG= True


