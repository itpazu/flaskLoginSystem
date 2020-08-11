import datetime


class User:

    @staticmethod
    def created_at():
        return datetime.datetime.now().date().isoformat()

    @staticmethod
    def updated_at():
        return datetime.datetime.now().isoformat()

    # added photo to constructor
    def __init__(self, _id, last_name, first_name, email, password, role, photo, token=None):

        self._id = str(_id)
        self.last_name = str(last_name)
        self.first_name = str(first_name)
        self.email = str(email)
        self.password = str(password)
        self.role = role
        self.creation_time = self.created_at()
        self.last_update_time = self.updated_at()
        self.photo = photo
        if token is not None:
            self.token = token
