from flask import request, jsonify
from models.user import User


class DataLayer:

    def add_user(self):
        first_name = request.get_json()['first_name']
        last_name = request.get_json()['last_name']
        username = request.get_json()['username']
        email = request.get_json()['email']
        admin = request.get_json()['admin']
        user_id = request.get_json()['user_id']
        password = self.encrypt_pass(request.get_json()['password'])
        if self.__db.Users.find_one({"email": email}):
            raise ValueError('The email is already in the system!')
        elif self.__db.Users.find_one({"user_id": user_id}):
            raise ValueError('The id number is already in the system!')
        elif self.__db.Users.find_one({"email": email}) and self.__db.Users.find_one({"user_id": user_id}):
            raise ValueError('The id number and email are already in the system!')
        else:
            new_user = User(user_id, last_name, first_name, username, email, password, admin)
            self.__db.Users.insert_one(new_user.__dict__)
            added_user = {'status': 'The user has been added!'}
            return added_user

    def encrypt_pass(self, password):
        return self.bcrypt.generate_password_hash(password).decode('utf-8')

    def __init__(self, bcrypt, client):
        self.__client = client
        self.__db = self.__client['keeperHome']
        self.bcrypt = bcrypt

    def delete_user(self, user_name):
        try:
            if self.__db.Users.find_one({"username": user_name}):
                self.__db.Users.delete_one({"username": user_name})
                users = {"status": 'The user has been deleted!'}
                return users
            else:
                raise ValueError('The username is not in the system!')
        except ValueError as error:
            raise error

    def make_admin(self, user_name):
        try:
            if self.__db.Users.find_one({"username": user_name}):
                if self.__db.Users.find_one({"username": user_name, "admin": False}):
                    self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"admin": True,
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

    def demote_admin(self, user_name):
        try:
            if self.__db.Users.find_one({"username": user_name}):
                if self.__db.Users.find_one({"username": user_name, "admin": True}):
                    self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"admin": False,
                                                                                           "last_update_time":
                                                                                               User.updated_at()}})
                    added_admin = {'status': 'The user is no longer an admin!'}
                    return added_admin
                else:
                    raise ValueError('The user is not an admin!')
            else:
                raise ValueError('The user does not exist!')
        except ValueError as error:
            raise error

    def change_first_name(self, user_name):
        first_name = request.get_json()['first_name']
        try:
            if self.__db.Users.find_one({"username": user_name}):
                self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"first_name": first_name,
                                                                                       "last_update_time":
                                                                                           User.updated_at()}})
                changed_name = {'status': 'The first name has been changed!'}
                return changed_name
            else:
                raise ValueError('The user does not exist!')
        except ValueError as error:
            raise error

    def change_last_name(self, user_name):
        last_name = request.get_json()['last_name']
        try:
            if self.__db.Users.find_one({"username": user_name}):
                self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"first_name": last_name,
                                                                                       "last_update_time":
                                                                                           User.updated_at()}})
                changed_name = {'status': 'The last name has been changed!'}
                return changed_name
            else:
                raise ValueError('The user does not exist!')
        except ValueError as error:
            raise error

    def change_email(self, user_name):
        email = request.get_json()['email']
        try:
            if self.__db.Users.find_one({"username": user_name}):
                if self.__db.Users.find({"$not": {"email": email}}):
                    self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"email": email,
                                                                                           "last_update_time":
                                                                                               User.updated_at()}})
                    changed_email = {'status': 'The email has been changed!'}
                    return changed_email
                else:
                    raise ValueError('This email is already in use!')
            else:
                raise ValueError('The user does not exist!')
        except ValueError as error:
            raise error

    def change_username(self, email):
        username = request.get_json()['username']
        try:
            if self.__db.Users.find_one({"email": email}):
                if self.__db.Users.find({"$not": {"username": username}}):
                    self.__db.Users.find_one_and_update({"email": email}, {"$set": {"username": username,
                                                                                    "last_update_time":
                                                                                        User.updated_at()}})
                    changed_username = {'status': 'The username has been changed!'}
                    return changed_username
                else:
                    raise ValueError('The username is already in use!')
            else:
                raise ValueError('The email does not exist!')
        except ValueError as error:
            raise error

    def change_user_id(self, user_name):
        user_id = request.get_json()['user_id']
        try:
            if self.__db.Users.find_one({"username": user_name}):
                if self.__db.Users.find({"$not": {"user_id": user_id}}):
                    self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"user_id": user_id,
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

    def change_password(self, user_name):
        password = self.encrypt_pass(request.get_json()['password'])
        try:
            if self.__db.Users.find_one({"username": user_name}):
                self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"password": password,
                                                                                       "last_update_time":
                                                                                           User.updated_at()}})
                changed_password = {'status': 'The password has been changed!'}
                return changed_password
            else:
                raise ValueError('The user does not exist!')
        except ValueError as error:
            raise error
