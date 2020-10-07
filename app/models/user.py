import datetime
from .base_class import BaseClass

class User(BaseClass):


    def __init__(self, _id, last_name, first_name, email, password, role, token=None):

        self._id = str(_id)
        self.last_name = str(last_name)
        self.first_name = str(first_name)
        self.email = str(email)
        self.password = str(password)
        self.role = role
        self.creation_time = self.updated_at()
        self.last_update_time = self.updated_at()
        if token is not None:
            self.token = token
