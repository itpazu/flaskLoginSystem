from flask import request, jsonify, json
from models.user import User
from Util import decode_token, encode_token, generate_id
import jwt
import secrets


class DataLayer:

    def all_users(self):
        users = self.__db.Users.find()
        return users

    def get_doc_by_email(self, email):

        user_dict = self.__db.Users.find_one({"email": email})
        if user_dict:
            return user_dict
        else:
            return None

    def get_doc_by_user_id(self, user_id):
        user_dict = self.__db.Users.find_one({"_id": user_id})
        if user_dict:
            return user_dict
        else:
            return None

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

    def log_user(self, email, password):

        verify_user_exists = self.get_doc_by_email(email)
        if verify_user_exists is None:
            raise ValueError('email does not exist in db')
        else:
            db_password = verify_user_exists["password"]
            compare_pass = self.match_password(db_password, password)
            role = verify_user_exists['role']
            if compare_pass:
                user_id = str(verify_user_exists['_id'])
                generated_token = encode_token(user_id, db_password, role)
                csrf_token = secrets.token_hex()
                self.store_token(user_id, generated_token, csrf_token)
                get_user_dict = self.get_doc_by_user_id(user_id)

                return get_user_dict

            raise ValueError('password is incorrect')

    def authenticate_user(self, user_id, token, csrf_token=None):

        user_from_db = self.get_doc_by_user_id(user_id)
        if user_from_db is None:
            raise ValueError('identification failed, user_id is either missing or incorrect')

        pass_from_db = user_from_db['password']
        decoded_token = decode_token(token, user_id, pass_from_db)

        try:
            if user_id != decoded_token['_id']:
                raise ValueError('ID do not match. please log in again')

        except Exception as e:
            raise e

        if csrf_token is not None:
            try:
                csrf_from_db = user_from_db['csrf_token']
                if str(csrf_token) != str(csrf_from_db):
                    raise ValueError('csrf token is invalid!')
            except ValueError as error:
                raise error

        return decoded_token


    def solcit_new_password(self, email):
        user_dic = self.get_doc_by_email(email)
        if user_dic is None:
            return None
        password = user_dic['password']
        user_id = user_dic['_id']
        role = user_dic['role']
        csrf_token = secrets.token_hex()

        try:
            token = encode_token(user_id, password, role)
        except Exception as error:
            raise error
        try:
            self.store_token(user_id, token, csrf_token)
        except Exception as error:
            raise ValueError('failed to update db')
        new_user_dic = self.get_doc_by_email(email)
        return new_user_dic



    def encrypt_pass(self, password):
        return self.bcrypt.generate_password_hash(password).decode('utf-8')

    def match_password(self, db_pass, received_password):
        if self.bcrypt.check_password_hash(db_pass, received_password):
            return True
        else:
            return False

    def store_token(self, user_id, token, csrf_token):
        store_token = self.__db.Users.update({"_id": user_id}, {"$set": {"token": token, 'csrf_token': csrf_token }})
        return store_token

    def delete_user(self, _id):
        try:
            if self.__db.Users.find_one({"_id": _id}):
                self.__db.Users.delete_one({"_id": _id})
                users = {"status": 'The user has been deleted!'}
                return users
            else:
                raise ValueError('The user is not in the system!')
        except ValueError as error:
            raise error

    def make_admin(self, _id):
        try:
            if self.__db.Users.find_one({"_id": _id}):
                if self.__db.Users.find_one({"_id": _id, "role": 'admin'}):
                    self.__db.Users.find_one_and_update({"_id": _id}, {"$set": {"role": 'admin',
                                                                                        "last_update_time":
                                                                                            User.updated_at()}})
                    added_admin = {'status': 'The user is now an admin!'}
                    return added_admin
                else:
                    raise ValueError('The user is already an admin!')
            else:
                raise ValueError('The user does not exist!')
        except ValueError as error:
            raise error

    def demote_admin(self, _id):
        try:
            if self.__db.Users.find_one({"_id": _id}):
                if self.__db.Users.find_one({"_id": _id, "role": 'admin'}):
                    self.__db.Users.find_one_and_update({"_id": _id}, {"$set": {"role": 'admin',
                                                                                        "last_update_time":
                                                                                            User.updated_at()}})
                    removed_admin = {'status': 'The user is no longer an admin!'}
                    return removed_admin
                else:
                    raise ValueError('The user is not an admin!')
            else:
                raise ValueError('The user does not exist!')
        except ValueError as error:
            raise error

    def change_first_name(self, _id):
        first_name = request.get_json()['first_name']
        try:
            if self.__db.Users.find_one({"_id": _id}):
                self.__db.Users.find_one_and_update({"_id": _id}, {"$set": {"first_name": first_name,
                                                                            "last_update_time": User.updated_at()}})
                changed_name = {'status': 'The first name has been changed!'}
                return changed_name
            else:
                raise ValueError('The user does not exist!')
        except ValueError as error:
            raise error

    def change_last_name(self, _id):
        last_name = request.get_json()['last_name']
        try:
            if self.__db.Users.find_one({"_id": _id}):
                self.__db.Users.find_one_and_update({"_id": _id}, {"$set": {"first_name": last_name,
                                                                            "last_update_time": User.updated_at()}})
                changed_name = {'status': 'The last name has been changed!'}
                return changed_name
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

    def change_id(self, email):
        _id = request.get_json()['_id']
        try:
            if self.__db.Users.find_one({"email": email}):
                if self.__db.Users.find({"$not": {"_id": _id}}):
                    self.__db.Users.find_one_and_update({"email": email}, {"$set": {"_id": _id,
                                                                                    "last_update_time":
                                                                                        User.updated_at()}})
                    changed_username = {'status': 'The user id has been changed!'}
                    return changed_username
                else:
                    raise ValueError('The user id is already in use!')
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

    def __init__(self, bcrypt, client):
        self.__client = client
        self.__db = self.__client['keeperHome']
        self.bcrypt = bcrypt
