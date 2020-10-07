from flask import request
from app.Util import encode_token, generate_id
from .Data_Layer import DataLayer
from app.models.user import User
import secrets

class DataLayerAdmin(DataLayer):
    def __init__(self):
        super().__init__()
        self.__db = self.get_db()
        self.users_collection = self.__db.Users


    def get_admins(self):
        try:
            admins = self.__db.Users.find({"role": "admin"}, {"email": 1, "_id": 0})
            return admins
        except Exception as error:
            raise Exception("failed to get admins: {}".format(str(error)))


    def add_user(self, content, conf=None):
        try:

            first_name = content['first_name']
            last_name = content['last_name']
            email = content['email']
            role = content['role']
            user_id = generate_id()
            password = self.encrypt_pass(secrets.token_hex()) if conf is None else self.encrypt_pass('12345678')
            token = encode_token(user_id, password, role)
            new_user = User(user_id, last_name, first_name, email, password, role, token)
            insert_new = self.users_collection.update({"email": email},
                                                {"$setOnInsert": (new_user.__dict__)}, upsert=True)
            if 'upserted' in insert_new:
                return self.get_doc_by_user_id('Users', insert_new['upserted'])
            else:
                raise Exception('user already exists!')

        except Exception as error:
            raise error

    def delete_user(self, _id):
        try:
            deleted = self.__db.Users.delete_one({"_id": _id})
            if deleted.deleted_count > 0:
                deleted = {"status": 'The user has been deleted!'}
                return deleted

        except Exception as error:
            raise Exception ({"message": "delete failed", "log": error, "status_code" : 400})


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
            else:
                password = self.encrypt_pass(secrets.token_hex())
                self.__db.Users.find_one_and_update({"email": email}, {"$set": {"password": password,
                                                                                "last_update_time": User.updated_at(),
                                                                                "blocked": True}},
                                                    upsert=True)
        except Exception as error:
            raise error
