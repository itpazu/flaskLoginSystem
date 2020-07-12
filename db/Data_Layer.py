from flask import request, json
from models.user import User
from Util import decode_token, encode_token
import jwt

class DataLayer:

    def get_doc_by_user_name(self, user_name):

        user_dict = self.__db.Users.find_one({"username": user_name})
        if user_dict:
            return user_dict
        else:
            return None

    def get_doc_by_user_id(self, user_id):
        user_dict = self.__db.Users.find_one({"user_id": user_id})
        if user_dict:
            return user_dict
        else:
            return None

    def add_user(self):
        first_name = request.get_json()['first_name']
        last_name = request.get_json()['last_name']
        user_name = request.get_json()['username']
        email = request.get_json()['email']
        admin = request.get_json()['admin']
        user_id = request.get_json()['user_id']
        password = self.encrypt_pass(request.get_json()['password'])
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

    def log_user(self, user_name, password):

        verify_user_exsits = self.get_doc_by_user_name(user_name)

        if verify_user_exsits is None:
            raise ValueError('email does not exist in db')

        else:
            db_password = verify_user_exsits["password"]
            # print(db_password)
            compare_pass = self.match_password(db_password, password)

            if compare_pass:
                user_id = str(verify_user_exsits['user_id'])
                generated_token = encode_token(user_id, db_password)
                store_token = self.store_token(user_id, generated_token)
                get_user_dict = self.get_doc_by_user_id(user_id)
                return get_user_dict

            raise ValueError('password is incorrect')

    def authenticate_user(self, user_id, token):

        user_from_db = self.get_doc_by_user_id(user_id)
        if user_from_db is None:
            raise ValueError('identification failed, user_id is either missing or incorrect')
        pass_from_db = user_from_db['password']
        decoded_token = decode_token(token, user_id, pass_from_db)

        try:
            if user_id != decoded_token:
                raise ValueError('Invalid session, please log in again')
            return True
        except jwt.ExpiredSignatureError:
            raise ValueError('Signature expired. Please log in again.')
        except jwt.InvalidTokenError:
            raise ValueError('Invalid token. Please log in again.')

        except ValueError as error:
            raise error




    def decrypt_pass(self, password):
        pass

    def encrypt_pass(self, password):
        return self.bcrypt.generate_password_hash(password).decode('utf-8')


    def match_password(self, db_pass, recieved_password):

        if self.bcrypt.check_password_hash(db_pass, recieved_password):
            return True
        else:
            return False

    def store_token(self, user_id, token):
        store_token = self.__db.Users.update({"user_id": user_id}, {"$set": {"token": token}})
        return store_token

    def __init__(self, bcrypt, client):

        self.__client = client
        self.__db = self.__client['keeperHome']
        self.bcrypt = bcrypt
