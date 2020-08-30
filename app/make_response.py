from flask import json, Response
from datetime import datetime, timedelta
from app.error_handler import ClientError

class ReturnResponse:

    @staticmethod
    def generate_response(msg):

        return Response(
            response=json.dumps(msg, default=str),
            status=200,
            mimetype="application/json")

    @staticmethod
    def response_with_headers(msg):

        return Response(
            response=json.dumps(msg, default=str),
            status=200,
            mimetype='application/json',
            headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                     'Access-Control-Allow-Credentials': "true",
                     'Access-Control-Allow-Headers': "Content-Type",
                     })

    @staticmethod
    def response_with_token(msg, token, fresh_token, csrf_token=None):
        response = Response(

            response=json.dumps(msg, default=str),
            status=200,
            mimetype='application/json',
            headers={'Access-Control-Allow-Origin': "http://localhost:3000",
                     'Access-Control-Allow-Credentials': "true",
                     'Access-Control-Allow-Headers': ["Content-Type", "Authorization"],
                     'Access-Control-Expose-Headers': ["Authorization"],
                     "Authorization": csrf_token if csrf_token is not None else None
                     })

        response.set_cookie('token', value=token, httponly=True,
                            domain='keepershomestaging-env.eba-b9pnmwmp.eu-central-1.elasticbeanstalk.com',
                            path='*', expires=datetime.utcnow() + timedelta(minutes=10), secure=True,
                            samesite='none')
        response.set_cookie('refresh_token', value=fresh_token, httponly=True,
                            domain='keepershomestaging-env.eba-b9pnmwmp.eu-central-1.elasticbeanstalk.com',
                            path='*', expires=datetime.utcnow() + timedelta(minutes=10), secure=True,
                            samesite='none')
        return response

    @staticmethod
    def error_response(error, path):
        if error.args:
            err = error.args[0]['message'] if "message" in error.args[0] else error
            log = error.args[0]['log'] if 'log' in error.args[0] else None
            status = error.args[0]['status_code'] if 'status_code' in error.args[0] else None
        else:
            err = error
            status = None
            log = None
        raise ClientError(str(err), path, status_code=status, log=log)
        # return Response(response=json.dumps(error), status=status, mimetype='application/json')

    @staticmethod
    def build_cors_preflight_response():
        response = Response(
            status=200,
            mimetype='application/json',
            headers={'Access-Control-Allow-Origin': "http://localhost:3000", 'Access-Control-Allow-Credentials': "true",
                     'Access-Control-Allow-Headers': ["Content-Type", "token", "credentials", "authorization"],
                     'Access-Control-Allow-Methods': '*'}

        )
        return response


    @staticmethod
    def log_error(message, path):
        try:
            ClientError.log_error(message, path)
        except Exception:
            pass

