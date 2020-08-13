from .Data_Layer_admin import DataLayerAdmin


class DataLayerProfile(DataLayerAdmin):
    def __init__(self):
        super().__init__()
        self.__db = self.get_db()

    def add_photo(self, _id, string):
        try:
            add_photo = self.__db.Users.update({"_id": _id}, {"$set": {"photo": string}})
            return add_photo
        except Exception as error:
            raise Exception('failed to add photo' + str(error))

    def delete_photo(self, _id):
        try:
            delete_photo = self.__db.Users.update({"_id": _id}, {"$set": {"photo": ""}})
            return delete_photo
        except Exception as error:
            raise Exception('failed to delete photo' + str(error))

    def edit_account_details(self, content):
        _id = content['_id']
        first_name = content['first_name']
        last_name = content['last_name']
        email = content['email']
        try:
            edit_user = self.__db.Users.find_one_and_update({"_id": _id}, {"$set": {"first_name": first_name,
                                                                                    "last_name": last_name,
                                                                                    "email": email}})
            return edit_user
        except Exception as error:
            raise Exception(error)