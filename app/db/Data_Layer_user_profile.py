from .Data_Layer_admin import DataLayerAdmin
from boto3 import client
import os
import datetime

UPLOAD_FOLDER = "uploads"


class DataLayerProfile(DataLayerAdmin):
    def __init__(self):
        super().__init__()
        self.__db = self.get_db()

    def upload_file(self, _id, f, bucket):
        d = datetime.datetime.now()
        chars = '-:. '
        for i in chars:
            d = str(d).replace(i, '')
        f.filename = f"{_id}{int(d)}.jpg"
        f.save(os.path.join(UPLOAD_FOLDER, f.filename))
        object_name = f"uploads/{f.filename}"
        s3_client = client('s3')

        for item in s3_client.list_objects_v2(Bucket=bucket, Prefix="uploads/")['Contents']:
            if item['Key'].startswith(f"uploads/{_id}"):
                s3_client.delete_object(Bucket=bucket, Key=item['Key'])

        response = s3_client.upload_file(f"uploads/{f.filename}", bucket, object_name)

        self.__db.Users.find_one_and_update({"_id": _id},
                                            {"$set": {"photo": f"https://{bucket}.s3.amazonaws.com/uploads/{_id}{int(d)}.jpg"}
                                             }, upsert=True)

        return response

    def delete_photo(self, _id, bucket):
        s3_client = client('s3')
        for item in s3_client.list_objects_v2(Bucket=bucket, Prefix="uploads/")['Contents']:
            if item['Key'].startswith(f"uploads/{_id}"):
                s3_client.delete_object(Bucket=bucket, Key=item['Key'])

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
