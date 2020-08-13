from datetime import datetime, timedelta
import jwt
import os
import random
import string


def encode_token(user_id, password, isAdmin):
    try:
        payload = {
            'exp': datetime.utcnow() + timedelta(minutes=1),
            'iat': datetime.utcnow(),
            'sub': user_id,
            'role': isAdmin
        }
        secret_key = os.environ.get('JWT_SECRET_KEY') + str(password) + user_id
        token = jwt.encode(
            payload,
            secret_key,
            algorithm='HS256',
        ).decode("utf-8")
        return token
    except Exception as e:
        raise ValueError('access token generation failed: {}'.format(str(e)))


def encode_refresh_token(user_id, password):

    try:
        payload = {
            'exp': datetime.utcnow() + timedelta(minutes=3),
            'iat': datetime.utcnow(),
            'sub': user_id,
        }
        secret_key = os.environ.get('JWT_SECRET_KEY') + user_id + str(password)
        token = jwt.encode(
            payload,
            secret_key,
            algorithm='HS256',
        ).decode("utf-8")
        return token
    except Exception as e:
        raise ValueError('refresh token generation failed: {}'.format(str(e)))


def decode_token(token, user_id, password):
    if token is None:
        raise ValueError('access token is missing from request')
    try:
        secret_key = os.environ.get('JWT_SECRET_KEY') + str(password) + user_id
        payload = jwt.decode(token, secret_key)
        return {"_id": payload['sub'], "role": payload['role']}

    except jwt.ExpiredSignatureError:
        raise Exception('Signature expired')
    except jwt.InvalidTokenError:
        raise Exception('invalid token')
    except Exception as error:
        raise Exception(str(error))


def decode_refresh_token(token, user_id, password):

    if token is None:
        raise ValueError('refresh token is missing from request')
    try:
        secret_key = os.environ.get('JWT_SECRET_KEY') + user_id + str(password)
        payload = jwt.decode(token, secret_key)

        return {"_id": payload['sub']}

    except jwt.ExpiredSignatureError:
        raise Exception('Signature expired')
    except jwt.InvalidTokenError:
        raise Exception('invalid token')
    except Exception as error:
        raise Exception(str(error))


def generate_id():
    return ''.join(random.choice(string.digits) for digit in range(8))
