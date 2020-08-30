from flask import current_app, jsonify
import datetime

class ClientError(Exception):
    status_code = 400


    def __init__(self, error, url, status_code=None, log=None):
        Exception.__init__(self)
        self.message = error
        self.instance = url
        if status_code is not None:
            self.status_code = status_code
        self.status_code = self.status_code
        if not log and self.status_code == 400:
            self.log = error
        else:
            self.log = log
        self.timestamp = self.get_time()

    def get_time(self):
        return datetime.datetime.now().strftime("%d-%m-%Y, %H:%M:%S")

    def to_dict(self):
        response = self.__dict__
        return response

    @staticmethod
    def log_error(message, path):
        try:
            current_app.logger.error('%s, originated in route: %s ' % (message,  path))
        # current_app.logger.error(error_to_log)

        except Exception:
            pass

@current_app.errorhandler(ClientError)
def handle_client_error(error):
    response_dict = error.to_dict()
    error_to_log = response_dict.pop("log")
    if error_to_log:
        try:
            current_app.logger.error('%s originated in route: %s ' % (error_to_log,  response_dict['instance']))
            # current_app.logger.error(error_to_log)

        except Exception as error:
            pass
    response = jsonify(response_dict)
    response.status_code = error.status_code
    return response
