from datetime import datetime, timedelta
import jwt
import os
import random
import string

def encode_token(user_id, password, isAdmin):


    try:
        payload = {
            'exp': datetime.utcnow() + timedelta(minutes=10),
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
        raise ValueError('token generation failed: {}'.format(str(e)))


def decode_token(token, user_id, password):
    if token is None:
        raise ValueError('token is missing from request')

    secret_key = os.environ.get('JWT_SECRET_KEY') + str(password) + user_id

    try:
        payload = jwt.decode(token, secret_key)

        return {"_id": payload['sub'], "role": payload['role']}
    except Exception as error:
        raise ValueError("token encoding error: " + str(error))





def generate_id():

    return ''.join(random.choice(string.digits) for digit in range(8))