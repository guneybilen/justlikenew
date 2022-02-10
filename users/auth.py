import datetime
import jwt
from django.conf import settings


def generate_access_token(user):
    access_token_payload = {
        'user_id': user.id,
        'nickname': user.nickname,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, minutes=0.5),
        'iat': datetime.datetime.utcnow(),
    }
    access_token = jwt.encode(access_token_payload,
                              settings.SECRET_KEY, algorithm='HS256')
    return access_token


def generate_refresh_token(user):
    refresh_token_payload = {
        'user_id': user.id,
        'nickname': user.nickname,
        # 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1),
        'iat': datetime.datetime.utcnow()
    }
    refresh_token = jwt.encode(
        refresh_token_payload, settings.REFRESH_TOKEN_SECRET, algorithm='HS256')
    return refresh_token


def generate_reset_token():
    reset_token_payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10),
        'iat': datetime.datetime.utcnow()
    }
    reset_token_payload = jwt.encode(
        reset_token_payload, settings.GENERATE_RESET_TOKEN, algorithm='HS256')

    return reset_token_payload
