from app import client
from app import bcrypt


class DataLayer():
    def __init__(self):
        self.bcrypt = bcrypt
        self.__db = client.db

    def get_db(self):
        return self.__db

    def encrypt_pass(self, password):
        return self.bcrypt.generate_password_hash(password).decode('utf-8')

    def match_password(self, db_pass, received_password):
        if self.bcrypt.check_password_hash(db_pass, received_password):
            return True
        else:
            return False
