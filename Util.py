from datetime import datetime, timedelta
import jwt
from decouple import config
import os

def encode_token(user_id, password):

    try:
        payload = {
            'exp': datetime.utcnow() + timedelta(minutes=10),
            'iat': datetime.utcnow(),
            'sub': user_id
        }
        # secret_key = config('JWT_SECRET_KEY') + str(password) + str(user_id)
        secret_key = os.environ.get('JWT_SECRET_KEY') + str(password) + user_id

        return jwt.encode(
            payload,
            secret_key,
            algorithm='HS256',
        ).decode("utf-8")

    except Exception as e:
        return e


def decode_token(token, user_id, password):

    if token is None:
        raise ValueError('token is missing from request')

    # secret_key = config('JWT_SECRET_KEY') + str(password) + str(user_id)
    secret_key = os.environ.get('JWT_SECRET_KEY') + str(password) + user_id

    try:
        payload = jwt.decode(token, secret_key)

        return payload['sub']
    except Exception as error:
        raise ValueError("token encoding error: " + str(error))


