import os
from dotenv import load_dotenv
from config import Config



class ConfigTests(Config):
    MONGO_URI = 'mongodb+srv://hogwartMain:Srjea3TVjAUX0M6u@cluster0.j0ehu.mongodb.net/Hogwarts-Tests?retryWrites=true&w=majority'
    MAIL_DEFAULT_SENDER = ('Hogwarts board', os.getenv('EMAIL'))
    ENV = 'testing'
    TESTING = True
    DEBUG= True


