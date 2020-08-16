from .Data_Layer_admin import DataLayerAdmin
from boto3 import client, resource


class DataLayerProfile(DataLayerAdmin):
    def __init__(self):
        super().__init__()
        self.__db = self.get_db()

    def upload_file(self, _id, file_name, bucket):
        object_name = file_name
        s3_client = client('s3')
        response = s3_client.upload_file(file_name, bucket, object_name)

        self.__db.Users.find_one_and_update({"_id": _id},
                                            {"$set": {"photo": f"https://{bucket}.s3.amazonaws.com/uploads/{file_name}"}
                                             })

        return response

    def delete_photo(self, _id, file_name, bucket):
        s3 = resource('s3')
        obj = s3.Object(bucket, file_name)
        obj.delete()

        self.__db.Users.find_one_and_update({"_id": _id}, {"$set": {"photo": ""}})

        return 'The photo has been deleted!'

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
