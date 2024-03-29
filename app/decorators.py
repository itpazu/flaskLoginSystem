from app.db.Data_Layer_auth import DataLayerAuth
from functools import wraps
from app.make_response import ReturnResponse
from flask import request
from app.error_handler import ClientError

db = DataLayerAuth()
reply= ReturnResponse()


class Decorators():

    @staticmethod
    def token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.method == "OPTIONS":
                return reply.build_cors_preflight_response()
            else:
                try:
                    try:
                        content = request.json or request.form or request.args
                        cookie = request.cookies
                        csrf_token = request.headers.get('Authorization')
                        if csrf_token is None:
                            raise Exception("csrf token")
                        token = cookie.get('token') or request.headers.get('token')
                        user_id = content.get('_id')
                    except Exception as error:
                        raise Exception('{} data is missing in the request'.format(str(error)))

                    db.authenticate_user(user_id, token, csrf_token)

                except Exception as err:
                    if str(err) == 'Signature expired':
                        raise ClientError("authentication failed", request.path, status_code=403, log=str(err))
                    else:
                        raise ClientError("authentication failed", request.path, status_code=401, log=str(err))

                return f(*args, **kwargs)

        return decorated

    @staticmethod
    def admin_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.method == "OPTIONS":
                return reply.build_cors_preflight_response()
            else:
                try:
                    try:
                        content = request.json or request.form or request.args
                        csrf_token = request.headers.get('Authorization')
                        cookie = request.cookies
                        token = cookie.get('token') or request.headers.get('token')
                        user_id = content['_id']
                        if csrf_token is None:
                            raise Exception("csrf token")
                    except Exception as error:
                        raise ValueError('{} data is missing in the request'.format(str(error)))

                    auth = db.authenticate_user(user_id, token, csrf_token)
                    if auth['role'] != 'admin':
                        raise Exception('user is not admin')

                except Exception as err:
                    if str(err) == 'Signature expired':
                        raise ClientError("authentication failed", request.path, status_code=403, log=str(err))
                    else:
                        raise ClientError("authentication failed", request.path, status_code=401, log=str(err))

                return f(*args, **kwargs)

        return decorated

    @staticmethod
    def refresh_token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                content = request.json
                cookie = request.cookies

                try:
                    ref_token = cookie.get('refresh_token') or request.headers.get('refresh_token')
                    user_id = content['_id']
                except Exception as error:
                    raise ValueError('{} data is missing in the request'.format(str(error)))

                authenticated_user = db.authenticate_refresh_token(user_id, ref_token)

            except Exception as err:
                raise ClientError("authentication failed", request.path, status_code=401, log=str(err))

            return f(authenticated_user, *args, **kwargs)

        return decorated
