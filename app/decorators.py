from app.db.Data_Layer_auth import DataLayerAuth
from functools import wraps
from flask import json, request
from flask import current_app

db = DataLayerAuth()


class Decorators:

    @staticmethod
    def token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                content = request.json
                cookie = request.cookies  # commented out for development only

                try:
                    csrf_token = request.headers.get('Authorization')
                    if csrf_token is None:
                        raise ValueError('csrf')
                    # token = request.headers.get('token')  # for dev only
                    token = cookie.get('token')
                    user_id = content['_id']
                except Exception as error:
                    raise ValueError('{} data is missing in the request'.format(str(error)))

                db.authenticate_user(user_id, token, csrf_token)

            except Exception as err:
                if str(err) == 'Signature expired':
                    response = current_app.response_class(
                        response=json.dumps("signature expired"),
                        status=403,
                        mimetype='application/json',

                    )
                    return response
                response = current_app.response_class(
                    response=json.dumps("authentication failed:" + str(err)),
                    status=401,
                    mimetype='application/json',

                )
                return response

            return f(*args, **kwargs)

        return decorated

    @staticmethod
    def admin_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                try:
                    content = request.json
                    csrf_token = request.headers.get('Authorization')

                    cookie = request.cookies  # commented out for development only
                    token = cookie.get('token')
                    # token = request.headers.get('token') ## dev only
                    user_id = content['_id']

                except Exception as error:
                    raise ValueError('{} data is missing in the request'.format(str(error)))

                auth = db.authenticate_user(user_id, token, csrf_token)
                if auth['role'] != 'admin':
                    raise Exception('user is not admin')

            except Exception as err:
                if str(err) == 'Signature expired':
                    response = current_app.response_class(
                        response=json.dumps("authentication failed:" + str(err)),
                        status=403,
                        mimetype='application/json',
                    )
                    return response

                response = current_app.response_class(
                    response=json.dumps("authentication failed:" + str(err)),
                    status=401,
                    mimetype='application/json',
                )
                return response
            return f(*args, **kwargs)

        return decorated

    @staticmethod
    def refresh_token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                content = request.json
                cookie = request.cookies  # commented out for development only

                try:
                    # ref_token = request.headers.get('refresh_token')  ##for dev only
                    ref_token = cookie.get('refresh_token')
                    user_id = content['_id']
                except Exception as error:
                    raise ValueError('{} data is missing in the request'.format(str(error)))

                authenticated_user = db.authenticate_refresh_token(user_id, ref_token)

            except Exception as err:
                response = current_app.response_class(
                    response=json.dumps("authentication failed:" + str(err)),
                    status=401,
                    mimetype='application/json',
                )

                return response

            return f(authenticated_user, *args, **kwargs)

        return decorated

    @staticmethod
    def build_cors_preflight_response():
        response = current_app.response_class(
            status=200,
            mimetype='application/json',
            headers={'Access-Control-Allow-Origin': "http://localhost:3000", 'Access-Control-Allow-Credentials': "true",
                     'Access-Control-Allow-Headers': ["Content-Type", "token"]}

        )
        return response
