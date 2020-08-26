from flask import json, request, Response
from datetime import datetime, timedelta


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
    def error_response(error, status=400):
        return Response(response=json.dumps(error), status=status, mimetype='application/json')

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


