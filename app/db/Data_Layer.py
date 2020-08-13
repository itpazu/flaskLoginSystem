from app import client
from app import bcrypt


class DataLayer():
    def __init__(self):
        self.bcrypt = bcrypt
        self.__db = client.db

        # self.__client = pymongo.MongoClient('10.150.54.176:27017', 27017, username=os.getenv("DB_USER_NAME"),
        #                                password=os.getenv("DB_PASSWORD"), authSource="admin")
        # self.__db= self.__client['keeperHome']

    def get_db(self):
        return self.__db

    def encrypt_pass(self, password):
        return self.bcrypt.generate_password_hash(password).decode('utf-8')

    def match_password(self, db_pass, received_password):
        if self.bcrypt.check_password_hash(db_pass, received_password):
            return True
        else:
            return False
