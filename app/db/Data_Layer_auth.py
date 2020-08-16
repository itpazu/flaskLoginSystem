from app.models.user import User
from app.Util import decode_token, encode_token, decode_refresh_token, encode_refresh_token
import secrets
from .Data_Layer_admin import DataLayerAdmin
from pymongo import ReturnDocument
from datetime import datetime


class DataLayerAuth(DataLayerAdmin):
    def __init__(self):
        super().__init__()
        self.__db = self.get_db()

    def log_user(self, email, password):

        verify_user_exists = self.get_doc_by_email(email)
        if verify_user_exists is None:
            raise ValueError('email does not exist in db')
        else:
            db_password = verify_user_exists["password"]
            compare_pass = self.match_password(db_password, password)
            if compare_pass:
                user_id = str(verify_user_exists['_id'])
                role = verify_user_exists['role']
                generated_access_token = encode_token(user_id, db_password, role)
                generated_refresh_token = encode_refresh_token(user_id, db_password)
                csrf_token = secrets.token_hex()
                user_dic = self.store_token(user_id, generated_access_token, csrf_token, generated_refresh_token)

                return user_dic

    def authenticate_user(self, user_id, token, csrf_token=None):

        user_from_db = self.get_doc_by_user_id(user_id)
        if user_from_db is None:
            raise ValueError('identification failed, user_id is either missing or incorrect')

        pass_from_db = user_from_db['password']

        try:
            decoded_token = decode_token(token, user_id, pass_from_db)

        except Exception as error:
            raise Exception(error)

        if user_id != decoded_token['_id']:
            raise Exception('ID do not match. please log in again')

        if csrf_token is not None:
            csrf_from_db = user_from_db['csrf_token']
            if str(csrf_token) != str(csrf_from_db):
                raise Exception('csrf token is invalid!')

        return decoded_token

    def authenticate_refresh_token(self, user_id, refresh_token):
        try:
            user_dic = self.get_doc_by_user_id(user_id)
            if user_dic is None:
                raise ValueError('identification failed, user_id is either missing or incorrect')
            password = user_dic['password']
            decode_refresh_token(refresh_token, user_id, password)
            return user_dic
        except Exception as error:
            raise Exception(str(error))

    def refresh_token(self, user_dic):
        try:
            user_id = user_dic['_id']
            password = user_dic['password']
            role = user_dic['role']

            refresh_token = encode_refresh_token(user_id, password)
            access_token = encode_token(user_id, password, role)

            self.store_fresh_tokens(user_id, access_token, refresh_token)

            return {'access_token': access_token, 'refresh_token': refresh_token}

        except Exception as error:
            raise Exception(str(error))

    def solicit_new_password(self, email):
        try:
            user_dic = self.get_doc_by_email(email)
            if user_dic is None:
                return None
            attempts = self.get_attempts(email)

            if attempts is not None and attempts["attempts"] >= 10:
                raise Exception('user is blocked. Turn to an admin')

            password = user_dic['password']
            user_id = user_dic['_id']
            role = user_dic['role']

            reset_token = encode_token(user_id, password, role)

            new_user_dic = self.store_reset_token(user_id, reset_token)

            return new_user_dic

        except Exception as error:
            raise error

    def store_token(self, user_id, access_token, csrf_token, refresh_token):
        try:
            store_token = self.__db.Users.find_one_and_update({"_id": user_id}, {"$set": {"token": access_token,
                                                                                          'csrf_token': csrf_token,
                                                                                          'refresh_token':
                                                                                              refresh_token}},
                                                              {"password": 0, "creation_time": 0,
                                                               "last_update_time": 0},
                                                              return_document=ReturnDocument.AFTER)
            return store_token

        except Exception as error:
            raise Exception('failed to store token' + str(error))

    def store_fresh_tokens(self, user_id, access_token, refresh_token):
        try:
            store_token = self.__db.Users.update({"_id": user_id}, {"$set": {"token": access_token,
                                                                             'refresh_token': refresh_token}})
            return store_token
        except Exception as error:
            raise Exception('failed to store token' + str(error))

    def store_reset_token(self, user_id, access_token):
        try:
            store_token = self.__db.Users.find_one_and_update({"_id": user_id}, {"$set": {"token": access_token}},
                                                              return_document=ReturnDocument.AFTER)
            return store_token
        except Exception as error:
            raise ('failed to store token' + str(error))

    def change_password(self, content):
        try:
            user_id = content['_id']
            password = content['password']
            confirm_pass = content['confirm_password']

        except Exception as error:
            raise ValueError('{} data is missing'.format(str(error)))

        if password != confirm_pass:
            raise ValueError('passwords do not match')

        hashedpass = self.encrypt_pass(password)

        try:
            changed_password = self.__db.Users.find_one_and_update({"_id": user_id}, {"$set": {"password": hashedpass,
                                                                                               "last_update_time":
                                                                                                   User.updated_at()}})
            if changed_password is None:
                raise ValueError('User might not exists in db')
            return changed_password['_id']

        except Exception as error:
            raise error

    def log_attempt(self, email):
        try:
            email_attempts = self.__db.emailAttempts.find_one_and_update({"email": email},
                                                                         {"$inc": {"attempts": 1},
                                                                          "$set": {"creation": datetime.utcnow()}},
                                                                         upsert=True,
                                                                         return_document=ReturnDocument.AFTER)
            return email_attempts

        except Exception as error:
            raise error

    def get_attempts(self, email):
        try:
            return self.__db.emailAttempts.find_one({"email": email}, {"attempts": 1, "_id": 0})
        except Exception as error:
            raise error
