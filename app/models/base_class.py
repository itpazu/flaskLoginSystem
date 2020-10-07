import datetime


class BaseClass:

    @staticmethod
    def updated_at():
        return datetime.datetime.now().date().strftime('%d-%m-%Y')