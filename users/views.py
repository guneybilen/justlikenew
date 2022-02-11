from django.contrib.auth.models import AnonymousUser
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404, redirect
from rest_framework import status
from items.permissions import IsOwnerOrReadOnly
from .serializers import UserSerializer
from rest_framework.response import Response
from users.models import CustomUser
from django.contrib.auth import get_user_model
from rest_framework import exceptions
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly, IsAuthenticated
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from .auth import generate_access_token, generate_refresh_token, generate_reset_token, generate_activate_account_token
from django.utils.translation import gettext as _
import jwt
from django.conf import settings
import sha512_crypt


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


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def users_view(request):
    print(request.data)
    if request.method == 'POST':
        User = get_user_model()
        username = request.data.get('email')
        password = request.data.get('password')
        passwordConfirm = request.data.get('passwordConfirm')
        nickname = request.data.get('nickname')
        s_name = request.data.get('s_name')
        s_answer = request.data.get('s_answer')

        if (username in [None, '', 'nul']) or (password in [None, '', 'nul']) or (
                passwordConfirm in [None, '', 'nul']) or (nickname in [None, '', 'nul']) or (
                s_answer in [None, '', 'nul']):
            return Response({"message": 'username, password, nickname and security answer are required'},
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
            return Response({"message": 'password and password confirmation needs to be the same value'},
                            status=status.HTTP_406_NOT_ACCEPTABLE)

        if s_answer == '':
            return Response({"message": 'security question and security answer must be provided'},
                            status=status.HTTP_406_NOT_ACCEPTABLE)

        if s_name not in [(tag.name) for tag in CustomUser().SecurityType]:
            return Response({"message": 'security question must be selected'},
                            status=status.HTTP_406_NOT_ACCEPTABLE)

        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            user = CustomUser.objects.filter(email=username).first()
            user.save()
            activate_token = generate_activate_account_token(user)
            subject = 'justlikenew.shop - Verify Your Email'
            message = """Please follow the link below for activating your account 
                                    http://localhost:3000/activation/{activate_token}

                                    If you can not follow the link just copy the link and go to the url address.

                                    Thanks,
                                    - justlikenew.shop team
                                    """.format(activate_token=activate_token)

            recepient = str(username)
            send_mail(subject,
                      message, 'a@a.com', [recepient], fail_silently=False)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PUT", "DELETE"])
@permission_classes([IsOwnerOrReadOnly])
@csrf_exempt
def user_detail(request, pk):
    user = CustomUser.objects.get(pk=pk)
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
            refresh_token_view(request)
            # return Response(serializer.data, status=status.HTTP_200_OK)
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
@csrf_exempt
def login_view(request):
    User = get_user_model()
    username = request.data.get('email')
    password = request.data.get('password')
    response = Response()
    if (username in [None, '', 'nul']) or (password in [None, '', 'nul']):
        print('username and password required')
        return Response({'status': 401})

    user = User.objects.filter(email=username).first()
    if (user is None):
        print('user not found')
        return Response({'status': 401})
    if (not user.check_password(password)):
        print('wrong email or wrong password')
        return Response({'status': 401})
    if user.is_active == False:
        return Response({'status': 403})

    serialized_user = UserSerializer(user).data

    access_token = generate_access_token(user)
    refresh_token = generate_refresh_token(user)
    user.refresh_token = refresh_token
    user.save()

    response.data = {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': serialized_user,
    }
    return response


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def logout_view(request):
    if request.method == 'POST':
        if request.user == AnonymousUser:
            return Response({"access_token": None, "refresh_token": None, 'user': None},
                            status=status.HTTP_202_ACCEPTED)
        User = get_user_model()
        if request.headers.get('refresh').endswith('null') or request.headers.get('refresh') is None:
            return Response(status=status.HTTP_406_NOT_ACCEPTABLE)
        refresh_token = request.headers.get('refresh').split(' ')[1]
        payload = jwt.decode(
            refresh_token, settings.REFRESH_TOKEN_SECRET, algorithms=['HS256'])
        user = User.objects.filter(id=payload['user_id']).first()
        user.refresh_token = None
        user.save()
        return Response({"access_token": None, "refresh_token": None, 'user': None}, status=status.HTTP_202_ACCEPTED)
    return Response(status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@csrf_exempt
def refresh_token_view(request):
    if request.user == AnonymousUser:
        return Response({"access_token": None, "refresh_token": None, 'user': None},
                        status=status.HTTP_401_UNAUTHORIZED)
    try:
        User = get_user_model()
        user = User.objects.filter(nickname=request.user).first()
        if not user:
            return Response(
                {'access_token': None, 'refresh_token': None, 'user': None, 'status': 'signin or signup'})
        return Response(
            {'refresh_token': user.refresh_token, 'user_id': user.id,
             'nickname': user.nickname}, status=status.HTTP_200_OK)
    except Exception as e:
        print("in users/view.py", e)
        return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([AllowAny])
@csrf_exempt
def get_security_questions(request):
    return Response({"names": [(tag.name) for tag in CustomUser().SecurityType],
                     "values": [(tag.value) for tag in CustomUser().SecurityType]})


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def passwordreset(request):
    if request.method == 'POST':
        email = request.data.get('username')
        if email in [None, '', 'null']:
            return Response({"state": 'please enter your email address'},
                            status=status.HTTP_406_NOT_ACCEPTABLE)

        user = CustomUser.objects.filter(email=email).first()
        if not user:
            print('no user with this email')
            return Response(
                {'state': "if there is an account associated with this email we will send an email"})
        subject = 'justlikenew.shop - Password Reset Email'
        reset_token = generate_reset_token(user)
        message = """Please follow the link below for resetting you password 
                     http://localhost:3000/newpassword/{reset_token}
                     
                     If you can not follow the link just copy the link and go to the url address.
                     
                     Thanks,
                     - justlikenew.shop team
                     """.format(reset_token=reset_token)

        recepient = str(email)
        send_mail(subject,
                  message, 'a@a.com', [recepient], fail_silently=False)
        return Response({'state': "if there is an account associated with this email we will send an email"})
    return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def getsecretquestion(request, token):
    if request.method == 'POST':
        token = request.data.get('token')
        if token in [None, '', 'null']:
            return Response({"state": 'sent data must had had a token'}, status=status.HTTP_406_NOT_ACCEPTABLE)

    try:
        payload = jwt.decode(
            token, settings.GENERATE_RESET_TOKEN, algorithms=['HS256'])
    except jwt.exceptions.InvalidSignatureError:
        return Response({"state": 'token has invalid signature.'},
                        status=status.HTTP_406_NOT_ACCEPTABLE)
    except jwt.exceptions.ExpiredSignatureError:
        return Response({"state": 'token is expired please request again.'},
                        status=status.HTTP_408_REQUEST_TIMEOUT)
    user = CustomUser.objects.filter(id=payload['user_id']).first()

    if user:
        return Response({"secretquestion": CustomUser.SecurityType[user.s_name].value})
    return Response(status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def passwordresetcomplete(request):
    if request.method == 'POST':
        password = request.data.get('password')
        passwordConfirm = request.data.get('passwordConfirm')
        token = request.data.get('token')
        answer = request.data.get('answer')

        if password in [None, '', 'null'] or passwordConfirm in [None, '', 'null'] or answer in [None, '', 'null']:
            return Response({"state": 'please provide all the information'},
                            status=status.HTTP_406_NOT_ACCEPTABLE)

        if password != passwordConfirm:
            return Response({"state": 'password and password confirmation do not match'},
                            status=status.HTTP_406_NOT_ACCEPTABLE)

        result = validate_password_strength(password)

        if result is not None:
            return Response({"state": result}, status=status.HTTP_406_NOT_ACCEPTABLE)

        try:
            payload = jwt.decode(
                token, settings.GENERATE_RESET_TOKEN, algorithms=['HS256'])
        except jwt.exceptions.InvalidSignatureError:
            return Response({"state": 'token has invalid signature.'},
                            status=status.HTTP_406_NOT_ACCEPTABLE)
        except jwt.exceptions.ExpiredSignatureError:
            return Response({"state": 'token is expired please request again.'},
                            status=status.HTTP_408_REQUEST_TIMEOUT)

        user = CustomUser.objects.filter(id=payload['user_id']).first()

        if sha512_crypt.verify(answer.strip(), user.s_answer):
            print("It Matches!")
            user.set_password(password)
            user.save()
            return Response({'state': 'password is changed'})
        else:
            print("It Does not Match :(")
            return Response({"state": "security question's answer does not match with our database records"},
                            status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def accountactivate(request, token):
    if request.method == 'POST':
        token = request.data.get('token')

        try:
            payload = jwt.decode(
                token, settings.GENERATE_RESET_TOKEN, algorithms=['HS256'])
        except jwt.exceptions.InvalidSignatureError:
            return Response({"state": 'token has invalid signature.'},
                            status=status.HTTP_406_NOT_ACCEPTABLE)
        except jwt.exceptions.ExpiredSignatureError:
            return Response({"state": 'token is expired please request again.'},
                            status=status.HTTP_408_REQUEST_TIMEOUT)

        user = CustomUser.objects.filter(id=payload['user_id']).first()
        user.is_active = True
        user.save()
        return Response({"state": 'activation successfully completed.'},
                        status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def accountactivaterepeatrequest(request):
    username = request.data.get('username')

    user = CustomUser.objects.filter(email=username).first()
    activate_token = generate_activate_account_token(user)
    subject = 'justlikenew.shop - Verify Your Email'
    message = """Please follow the link below for activating your account 
                                       http://localhost:3000/activation/{activate_token}

                                       If you can not follow the link just copy the link and go to the url address.

                                       Thanks,
                                       - justlikenew.shop team
                                       """.format(activate_token=activate_token)

    recepient = str(username)
    send_mail(subject,
              message, 'a@a.com', [recepient], fail_silently=False)
    return Response({"state": 'We just sent you an email. Please, check your email ' +
                              'inbox follow the link in order to activate your account'},
                    status=status.HTTP_201_CREATED)