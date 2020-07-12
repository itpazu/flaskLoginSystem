from flask import request, jsonify
from models.user import User


class DataLayer:

    def get_doc(self, user_name):
        user_dict = self.__db.Users.find_one({"username": user_name})
        if user_dict:
            return user_dict
        else:
            resp = 'No such user name exists!'
        return resp

    def add_user(self):
        first_name = request.get_json()['first_name']
        last_name = request.get_json()['last_name']
        username = request.get_json()['username']
        email = request.get_json()['email']
        admin = request.get_json()['admin']
        user_id = request.get_json()['user_id']
        password = self.bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
        if self.__db.Users.find_one({"email": email}):
            added_user = {'status': 'The email is already in the system!'}
        elif self.__db.Users.find_one({"user_id": user_id}):
            added_user = {'status': 'The id number is already in the system!'}
        elif self.__db.Users.find_one({"email": email}) and self.__db.Users.find_one({"user_id": user_id}):
            added_user = {'status': 'The id number and email are already in the system!'}
        else:
            new_user = User(user_id, last_name, first_name, username, email, password, admin)
            self.__db.Users.insert_one(new_user.__dict__)
            added_user = {'status': 'The user has been added!'}
        return added_user

    def login(self):
        email = request.get_json()['email']
        password = request.get_json()['password']

        response = self.__db.Users.find_one({"email": email})

        if response:
            if bcrypt.check_password_hash(response['password'], password):
                access_token = create_access_token(identity={
                    'user_id': str(response['user_id']),
                    'first_name': response['first_name'],
                    'last_name': response['last_name'],
                    'email': response['email'],
                    'username': response['username'],
                    'admin': response['admin']
                })
                result = jsonify({'token': access_token})
            else:
                result = jsonify({"error": "Invalid username or password!"})
        else:
            result = jsonify({"result": "No results found"})
        return result

    def delete_user(self, user_name):
        try:
            if self.__db.Users.find_one({"username": user_name}):
                self.__db.Users.delete_one({"username": user_name})
                users = {"status": 'The user has been deleted!'}
            else:
                users = {"status": 'The username is not in the system!'}
            return users
        except Exception as e:
            print(e)

    def make_admin(self, user_name):
        try:
            if self.__db.Users.find_one({"username": user_name}):
                if self.__db.Users.find_one({"username": user_name, "admin": False}):
                    self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"admin": True,
                                                                                           "last_update_time":
                                                                                               User.updated_at()}})
                    added_admin = {'status': 'The user is now an admin!'}
                else:
                    added_admin = {'status': 'The user is already an admin!'}
            else:
                added_admin = {'status': 'The user does not exist!'}
            return added_admin
        except Exception as e:
            print(e)

    def demote_admin(self, user_name):
        try:
            if self.__db.Users.find_one({"username": user_name}):
                if self.__db.Users.find_one({"username": user_name, "admin": True}):
                    self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"admin": False,
                                                                                           "last_update_time":
                                                                                               User.updated_at()}})
                    added_admin = {'status': 'The user is no longer an admin!'}
                else:
                    added_admin = {'status': 'The user is not an admin!'}
            else:
                added_admin = {'status': 'The user does not exist!'}
            return added_admin
        except Exception as e:
            print(e)

    def change_first_name(self, user_name):
        first_name = request.get_json()['first_name']
        try:
            if self.__db.Users.find_one({"username": user_name}):
                self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"first_name": first_name,
                                                                                       "last_update_time":
                                                                                           User.updated_at()}})
                changed_name = {'status': 'The first name has been changed!'}
            else:
                changed_name = {'status': 'The user does not exist!'}
            return changed_name
        except Exception as e:
            print(e)

    def change_last_name(self, user_name):
        last_name = request.get_json()['last_name']
        try:
            if self.__db.Users.find_one({"username": user_name}):
                self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"first_name": last_name,
                                                                                       "last_update_time":
                                                                                           User.updated_at()}})
                changed_name = {'status': 'The last name has been changed!'}
            else:
                changed_name = {'status': 'The user does not exist!'}
            return changed_name
        except Exception as e:
            print(e)

    def change_email(self, user_name):
        email = request.get_json()['email']
        try:
            if self.__db.Users.find_one({"username": user_name}):
                if self.__db.Users.find({"$not": {"email": email}}):
                    self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"email": email,
                                                                                           "last_update_time":
                                                                                               User.updated_at()}})
                    changed_email = {'status': 'The email has been changed!'}
                else:
                    changed_email = {'status': 'This email is already in use!'}
            else:
                changed_email = {'status': 'The user does not exist!'}
            return changed_email
        except Exception as e:
            print(e)

    def change_username(self, email):
        username = request.get_json()['username']
        try:
            if self.__db.Users.find_one({"email": email}):
                if self.__db.Users.find({"$not": {"username": username}}):
                    self.__db.Users.find_one_and_update({"email": email}, {"$set": {"username": username,
                                                                                    "last_update_time":
                                                                                        User.updated_at()}})
                    changed_username = {'status': 'The username has been changed!'}
                else:
                    changed_username = {'status': 'The username is already in use!'}
            else:
                changed_username = {'status': 'The email does not exist!'}
            return changed_username
        except Exception as e:
            print(e)

    def change_user_id(self, user_name):
        user_id = request.get_json()['user_id']
        try:
            if self.__db.Users.find_one({"username": user_name}):
                if self.__db.Users.find({"$not": {"user_id": user_id}}):
                    self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"user_id": user_id,
                                                                                           "last_update_time":
                                                                                               User.updated_at()}})
                    changed_username = {'status': 'The user id has been changed!'}
                else:
                    changed_username = {'status': 'The user id is already in use!'}
            else:
                changed_username = {'status': 'The user does not exist!'}
            return changed_username
        except Exception as e:
            print(e)

    def change_password(self, user_name):
        password = self.bcrypt.generate_password_hash(request.get_json()['password']).decode('utf-8')
        try:
            if self.__db.Users.find_one({"username": user_name}):
                self.__db.Users.find_one_and_update({"username": user_name}, {"$set": {"password": password,
                                                                                       "last_update_time":
                                                                                           User.updated_at()}})
                changed_password = {'status': 'The password has been changed!'}
            else:
                changed_password = {'status': 'The user does not exist!'}
            return changed_password
        except Exception as e:
            print(e)

    def __init__(self, bcrypt, client):
        self.__client = client
        self.__db = self.__client['keeperHome']
        self.bcrypt = bcrypt
