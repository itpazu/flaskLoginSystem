from flask import request
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
        user_name = request.get_json()['username']
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
            new_user = User(user_id, last_name, first_name, user_name, email, password, admin)
            self.__db.Users.insert_one(new_user.__dict__)
            added_user = {'status': 'The user has been added!'}
        return added_user



    def __init__(self, bcrypt, client):

        self.__client = client
        self.__db = self.__client['keeperHome']
        self.bcrypt = bcrypt
