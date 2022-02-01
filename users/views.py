from django.shortcuts import get_object_or_404
from rest_framework import status
from items.permissions import IsOwnerOrReadOnly
from .models import CustomUser
from .serializers import UserSerializer
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from rest_framework import exceptions
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from django.views.decorators.csrf import ensure_csrf_cookie
from .auth import generate_access_token, generate_refresh_token
from django.views.decorators.csrf import csrf_protect
from django.utils.translation import gettext as _
import jwt
from django.conf import settings


def validate_password_strength(value):
    """Validates that a password is as least 7 characters long and has at least
    1 digit and 1 letter.
    """
    min_length = 7

    if len(value) < min_length:
        return _('password must be at least {0} characters long.').format(min_length)

    # check for digit
    if not any(char.isdigit() for char in value):
        return _('password must contain at least 1 digit.')

    # check for letter
    if not any(char.isalpha() for char in value):
        return _('password must contain at least 1 letter.')

    return None


@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def users_view(request):
    # if request.method == 'GET':
    #     data = CustomUser.objects.all()
    #
    #     serializer = UserSerializer(data, context={'request': request}, many=True)
    #
    #     return Response(serializer.data)

    if request.method == 'POST':
        User = get_user_model()
        # print(request.data)
        username = request.data.get('email')
        password = request.data.get('password')
        passwordConfirm = request.data.get('passwordConfirm')
        nickname = request.data.get('nickname')
        if (username is None) or (password is None) or (passwordConfirm is None) or (nickname is None):
            return Response({"message": 'username, password, password information, and nickname are required'},
                            status=status.HTTP_406_NOT_ACCEPTABLE)

        forEmailCheck = User.objects.filter(email=username).exists()
        if forEmailCheck:
            return Response({"message": 'email in use'},
                            status=status.HTTP_409_CONFLICT)
        forNickNameCheck = User.objects.filter(nickname=nickname).exists()
        if forNickNameCheck:
            return Response({"message": 'nickname in use'}, status=status.HTTP_409_CONFLICT)

        result = validate_password_strength(password)

        if result is not None:
            return Response({"message": result}, status=status.HTTP_406_NOT_ACCEPTABLE)

        if password != passwordConfirm:
            raise exceptions.AuthenticationFailed(
                'password and password confirmation needs to be the same value')
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PUT", "DELETE"])
@permission_classes([IsOwnerOrReadOnly])
def user_detail(request, pk):
    user = CustomUser.objects.get(pk=pk)
    # print('user', user)
    if not user:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        try:
            serializer = UserSerializer(user, context={'request': request}, many=True)
        except Exception as e:
            # print("in users.views.py ", e);
            return Response(status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.data)

    if request.method == 'PUT':
        serializer = UserSerializer(user, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET'])
@permission_classes([AllowAny])
def user(request):
    user = request.user
    serialized_user = UserSerializer(user).data
    return Response({'user': serialized_user})


@api_view(['POST'])
@permission_classes([AllowAny], )
@authentication_classes([])
@ensure_csrf_cookie
def login_view(request):
    User = get_user_model()
    username = request.data.get('email')
    password = request.data.get('password')
    response = Response()
    if (username is None) or (password is None):
        raise exceptions.AuthenticationFailed(
            'username and password required')

    # user = User.objects.filter(username=username).first()
    user = User.objects.filter(email=username).first()
    if (user is None):
        raise exceptions.AuthenticationFailed('user not found')
    if (not user.check_password(password)):
        raise exceptions.AuthenticationFailed('wrong email or wrong password')

    serialized_user = UserSerializer(user).data

    access_token = generate_access_token(user)
    refresh_token = generate_refresh_token(user)

    response.set_cookie(key='refreshtoken', value=refresh_token, httponly=True)
    response.set_cookie(key='loggedIn', value=True)
    response.data = {
        'access_token': access_token,
        'user': serialized_user,
    }
    return response


@api_view(['GET'])
@permission_classes([AllowAny], )
@ensure_csrf_cookie
def logout_view(request):
    response = Response()
    response.delete_cookie(key='refreshtoken')
    response.delete_cookie(key='loggedIn')
    return response


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_protect
def refresh_token_view(request):
    User = get_user_model()
    refresh_token = request.COOKIES.get('refreshtoken')
    # print('users/views.py refresh_token', refresh_token)
    if refresh_token is None:
        # raise exceptions.AuthenticationFailed(
        #     'Authentication credentials were not provided.')
        return Response(status=status.HTTP_204_NO_CONTENT)
    try:
        payload = jwt.decode(
            refresh_token, settings.REFRESH_TOKEN_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        print('users/views.py')
        response = Response()
        response.delete_cookie("refreshtoken")
        response.delete_cookie("loggedIn")
        # you canot do the following; raises ~ "Nonetype object can not have assignment error"
        # response.data['info'] = 'expired refresh token, please login again.'
        # response.data['status_code'] = status.HTTP_204_NO_CONTENT
        return response
    except jwt.InvalidSignatureError:
        raise jwt.InvalidSignatureError(
            'InvalidSignatureError -  tokens are not same when encoded and decoded by guney')
    user = User.objects.filter(id=payload.get('user_id')).first()
    if user is None:
        raise exceptions.AuthenticationFailed('User not found')

    if not user.is_active:
        raise exceptions.AuthenticationFailed('user is inactive')

    access_token = generate_access_token(user)
    return Response({'access_token': access_token, 'user_id': user.id, 'nickname': user.nickname})
