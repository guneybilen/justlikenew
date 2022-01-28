import jwt
from rest_framework.authentication import BaseAuthentication
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
        authorization_heaader = request.headers.get('Auth')
        refresh_token = request.COOKIES.get('refreshtoken')
        # print('User', User)
        # print("Auth", request.headers.get('Auth'))
        if authorization_heaader == 'Bearer null' or not authorization_heaader or authorization_heaader.startswith(
                "Token"):
            return None
        try:
            access_token = authorization_heaader.split(' ')[1]
            # print('access_token', access_token)
            # print('refresh_token', refresh_token)
            if refresh_token:
                print('verify.py')
                payload = jwt.decode(
                    refresh_token, settings.REFRESH_TOKEN_SECRET, algorithms=['HS256']) or jwt.decode(
                    access_token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('access_token and refresh_token has expired')
        except IndexError:
            raise exceptions.AuthenticationFailed('Auth prefix missing')

        user = User.objects.filter(id=payload['user_id']).first()
        if user is None:
            raise exceptions.AuthenticationFailed('User not found')

        if not user.is_active:
            raise exceptions.AuthenticationFailed('user is inactive')

        self.enforce_csrf(request)
        return (user, None)

    def enforce_csrf(self, request):
        check = CSRFCheck(request)
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)
