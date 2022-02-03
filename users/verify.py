import jwt
from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import BaseAuthentication
from rest_framework.response import Response

from django.middleware.csrf import CsrfViewMiddleware
from rest_framework import exceptions
from django.conf import settings
from django.contrib.auth import get_user_model


class CSRFCheck(CsrfViewMiddleware):
    def _reject(self, request, reason):
        return reason


class JWTAuthentication(BaseAuthentication):

    def authenticate(self, request):
        User = get_user_model()
        authorization_heaader_access = request.headers.get('access')
        authorization_heaader_refresh = request.headers.get('refresh')
        access_token = authorization_heaader_access and authorization_heaader_access.split(' ')[1]
        refresh_token = authorization_heaader_refresh and authorization_heaader_refresh.split(' ')[1]
        if refresh_token == 'null' or refresh_token is None:
            print('Noneeeee')
            return AnonymousUser, None
        try:
            print('verify.py')
            print('refresh_token', refresh_token)
            payload = jwt.decode(
                refresh_token, settings.REFRESH_TOKEN_SECRET, algorithms=['HS256']) or jwt.decode(
                access_token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.filter(id=payload['user_id']).first()
        except jwt.ExpiredSignatureError:
            print('expired')
            return AnonymousUser, None
            # raise exceptions.AuthenticationFailed('access_token or refresh_token has expired')
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('User not found')
        # if user.refresh_token != refresh_token:
        #     print('refresh token has been altered')
        #     return AnonymousUser, None

        if not user.is_active:
            raise exceptions.AuthenticationFailed('user is inactive')

        # self.enforce_csrf(request)
        return (user, None)

    def enforce_csrf(self, request):
        check = CSRFCheck(request)
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)
