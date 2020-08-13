from flask import request
from app import client
from datetime import datetime
from pymongo import ReturnDocument
from app import bcrypt
# from app import DB
from app.models.user import User
from app.Util import decode_token, encode_token, generate_id, decode_refresh_token, encode_refresh_token
import secrets
# import os
# import pymongo
from dotenv import load_dotenv
load_dotenv()

class DataLayer():
    def __init__(self):
        self.bcrypt = bcrypt
        self.__db = client.db

        # self.__client = pymongo.MongoClient('10.150.54.176:27017', 27017, username=os.getenv("DB_USER_NAME"),
        #                                password=os.getenv("DB_PASSWORD"), authSource="admin")
        # self.__db= self.__client['keeperHome']

    def get_db(self):
        return self.__db

    def all_users(self):
        try:
            users = self.__db.Users.find()
            return users
        except Exception as e:
            raise Exception('db update failed: {} '.format(str(e)))

    def get_doc_by_email(self, email):
        try:
            user_dict = self.__db.Users.find_one({"email": email})
            if user_dict:
                return user_dict
            else:
                return None
        except Exception as error:
            raise Exception(str(error))

    def get_admins(self):
        try:
            admins = self.__db.Users.find({"role": "admin"}, {"email": 1, "_id": 0})
            return admins
        except Exception as error:
            raise Exception("failed to get admins: {}".format(str(error)))


    def get_doc_by_user_id(self, user_id):
        try:
            user_dict = self.__db.Users.find_one({"_id": user_id})

            if user_dict:
                return user_dict
            else:
                return None
        except Exception as error:
            raise Exception(str(error))

    def add_user(self, content):
        try:
            first_name = content['first_name']
            last_name = content['last_name']
            email = content['email']
            role = content['role']
            user_id = generate_id()
            check_if_user_exists = self.__db.Users.find_one({"$or": [{"email": email}, {"_id": user_id}]})
            if check_if_user_exists is not None:
                raise ValueError('user already exists!')
            else:
                password = self.encrypt_pass(secrets.token_hex())
                token = encode_token(user_id, password, role)
                new_user = User(user_id, last_name, first_name, email, password, role, token)
                self.__db.Users.insert_one(new_user.__dict__)
                added_user = self.get_doc_by_email(email)
                return added_user
        except Exception as error:
            raise error

    # def log_user(self, email, password):
    #
    #     verify_user_exists = self.get_doc_by_email(email)
    #     if verify_user_exists is None:
    #         raise ValueError('email does not exist in db')
    #     else:
    #         db_password = verify_user_exists["password"]
    #         compare_pass = self.match_password(db_password, password)
    #         if compare_pass:
    #             user_id = str(verify_user_exists['_id'])
    #             role = verify_user_exists['role']
    #             generated_access_token = encode_token(user_id, db_password, role)
    #             generated_refresh_token = encode_refresh_token(user_id, db_password)
    #             csrf_token = secrets.token_hex()
    #             user_dic = self.store_token(user_id, generated_access_token, csrf_token, generated_refresh_token)
    #
    #             return user_dic

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
                raise Exception('user is blocked. Turn to an main')

            password = user_dic['password']  # db
            user_id = user_dic['_id']
            role = user_dic['role']
            # generate new password

            reset_token = encode_token(user_id, password, role)

            new_user_dic = self.store_reset_token(user_id, reset_token)  # store new pass

            return new_user_dic

        except Exception as error:
            raise error

    def encrypt_pass(self, password):
        return self.bcrypt.generate_password_hash(password).decode('utf-8')

    def match_password(self, db_pass, received_password):
        if self.bcrypt.check_password_hash(db_pass, received_password):
            return True
        else:
            return False

    def store_token(self, user_id, access_token, csrf_token, refresh_token):
        try:
            store_token = self.__db.Users.find_one_and_update({"_id": user_id}, {"$set": {"token": access_token,
                                                                             'csrf_token': csrf_token,
                                                                             'refresh_token': refresh_token}}, {"password": 0, "creation_time": 0,
                                                                                                                "last_update_time": 0 },
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
            store_token = self.__db.Users.find_one_and_update({"_id": user_id}, {"$set": {"token": access_token}}, return_document=ReturnDocument.AFTER)
            return store_token
        except Exception as error:
            raise('failed to store token' + str(error))

    def delete_user(self, _id):
        try:
            deleted = self.__db.Users.delete_one({"_id": _id})
            if deleted.deleted_count > 0:
                users = {"status": 'The user has been deleted!'}
                return users
            else:
                raise ValueError('The user is not in the system!')
        except ValueError as error:
            raise error

    def make_admin(self, _id):
        try:
            if self.__db.Users.find_one({"_id": _id}):
                if self.__db.Users.find_one({"_id": _id, "role": 'main'}):
                    self.__db.Users.find_one_and_update({"_id": _id}, {"$set": {"role": 'main',
                                                                                        "last_update_time":
                                                                                            User.updated_at()}})
                    added_admin = {'status': 'The user is now an main!'}
                    return added_admin
                else:
                    raise ValueError('The user is already an main!')
            else:
                raise ValueError('The user does not exist!')
        except ValueError as error:
            raise error

    def demote_admin(self, _id):
        try:
            if self.__db.Users.find_one({"_id": _id}):
                if self.__db.Users.find_one({"_id": _id, "role": 'main'}):
                    self.__db.Users.find_one_and_update({"_id": _id}, {"$set": {"role": 'main',
                                                                                        "last_update_time":
                                                                                            User.updated_at()}})
                    removed_admin = {'status': 'The user is no longer an main!'}
                    return removed_admin
                else:
                    raise ValueError('The user is not an main!')
            else:
                raise ValueError('The user does not exist!')
        except ValueError as error:
            raise error


    def change_email(self, _id):
        email = request.get_json()['email']
        try:
            if self.__db.Users.find_one({"_id": _id}):
                if self.__db.Users.find({"$not": {"email": email}}):
                    self.__db.Users.find_one_and_update({"_id": _id}, {"$set": {"email": email,
                                                                                "last_update_time": User.updated_at()}})
                    changed_email = {'status': 'The email has been changed!'}
                    return changed_email
                else:
                    raise ValueError('This email is already in use!')
            else:
                raise ValueError('The user does not exist!')
        except ValueError as error:
            raise error


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


    def get_attempts(self, email):
        try:
            return self.__db.emailAttempts.find_one({"email": email}, {"attempts": 1, "_id": 0})
        except Exception as error:
            raise error

    def delete_ip_attempts(self, ip_address):
        try:
            self.__db.ipAttempts.find_one_and_delete({"ip_address": ip_address})
        except Exception as error:
            raise error



    def delete_block_field(self, email):
        try:
            self.__db.Users.update({"email": email}, {"$unset": {"blocked": 1}})

        except Exception as error:
            raise error

    def block_current_password(self, email, block=None):
        try:
            if block is None:
                password = self.encrypt_pass(secrets.token_hex())
                self.__db.Users.find_one_and_update({"email": email}, {"$set": {"password": password,
                                                                                "last_update_time": User.updated_at()}})


            password = self.encrypt_pass(secrets.token_hex())
            self.__db.Users.find_one_and_update({"email": email}, {"$set": {"password": password,
                                                                    "last_update_time": User.updated_at(), "blocked": True}},
                                                upsert=True)
        except Exception as error:
            raise error



    def delete_email_attempts(self, email):
        try:
            self.__db.emailAttempts.find_one_and_delete({"email": email})
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


# x = DataLayer()
# print(x.get_admins())