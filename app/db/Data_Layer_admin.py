from flask import request
from app.Util import encode_token, generate_id
from .Data_Layer import DataLayer
from app.models.user import User
import secrets

class DataLayerAdmin(DataLayer):
    def __init__(self):
        super().__init__()
        self.__db = self.get_db()
        # print(help(DataLayer_auth))


    def all_users(self):
        try:
            users = self.__db.Users.find()
            all_users_list = []

            for i in users:
                all_users_list.append(i)

            return all_users_list
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
            photo = ''
            user_id = generate_id()
            check_if_user_exists = self.__db.Users.find_one({"$or": [{"email": email}, {"_id": user_id}]})
            if check_if_user_exists is not None:
                raise ValueError('user already exists!')
            else:
                password = self.encrypt_pass(secrets.token_hex())
                token = encode_token(user_id, password, role)
                new_user = User(user_id, last_name, first_name, email, password, role, photo, token)
                self.__db.Users.insert_one(new_user.__dict__)
                added_user = self.get_doc_by_email(email)
                return added_user
        except Exception as error:
            raise error


    def delete_user(self, _id):
        try:
            deleted = self.__db.Users.delete_one({"_id": _id})
            if deleted.deleted_count > 0:
                deleted = {"status": 'The user has been deleted!'}
                return deleted
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


    def delete_ip_attempts(self, ip_address):
        try:
            self.__db.ipAttempts.find_one_and_delete({"ip_address": ip_address})
        except Exception as error:
            raise error

    def delete_email_attempts(self, email):
        try:
            self.__db.emailAttempts.find_one_and_delete({"email": email})
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
                                                                            "last_update_time": User.updated_at(),
                                                                            "blocked": True}},
                                                upsert=True)
        except Exception as error:
            raise error

