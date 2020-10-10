from app import client
from app import bcrypt


class DataLayer:
    def __init__(self):
        self.bcrypt = bcrypt
        self.__db = client.db
        # print(self.__db.list_collection_names())

    def get_db(self):
        return self.__db

    def encrypt_pass(self, password):
        try:
            return self.bcrypt.generate_password_hash(password).decode('utf-8')
        except Exception as error:
            raise Exception({'message': error})

    def match_password(self, db_pass, received_password):
        try:
            if self.bcrypt.check_password_hash(db_pass, received_password):
                return True
            else:
                return False
        except Exception as error:
            raise Exception({'message': error})

    def get_doc_by_user_id(self, collection, user_id):
        try:
            db_collection = getattr(self.__db, collection)
            user_dict = db_collection.find_one({"_id": user_id})
            if user_dict:
                return user_dict
            else:
                return None
        except Exception as error:
            raise Exception({'message': error})

    def get_doc_by_email(self, collection, email):
        try:
            db_collection = getattr(self.__db, collection)
            user_dict = db_collection.find_one({"email": email})
            if user_dict:
                return user_dict
            else:
                return None
        except Exception as error:
            raise Exception({'message': error})

    def all_users(self, collection):
        try:
            db_collection = getattr(self.__db, collection)
            users = db_collection.find({ }, { "csrf_token": 0, "token": 0, "refresh_token": 0, "password": 0 })

            all_users_list = list(users)
            if len(all_users_list) == 0:
                raise Exception('no documents to show')
            return all_users_list
        except Exception as e:
            raise Exception({'message': 'db update failed: {}'.format(str(e))})
