import json
import datetime


class User:

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__)

    @staticmethod
    def created_at():
        return datetime.datetime.now().date().isoformat()

    @staticmethod
    def updated_at():
        return datetime.datetime.now().isoformat()

    def __init__(self, user_id, last_name, first_name, username, email, password, admin):
        self.user_id = str(user_id)
        self.last_name = str(last_name)
        self.first_name = str(first_name)
        self.username = str(username)
        self.email = str(email)
        self.password = str(password)
        self.admin = admin
        self.creation_time = self.created_at()
        self.last_update_time = self.updated_at()
