from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from items.permissions import IsOwnerOrReadOnly

from .serializers import *


@api_view(['GET', 'POST'])
@permission_classes([IsOwnerOrReadOnly])
def users(request):
    # if request.method == 'GET':
    #     data = CustomUser.objects.all()
    #
    #     serializer = UserSerializer(data, context={'request': request}, many=True)
    #
    #     return Response(serializer.data)

    if request.method == 'POST':
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PUT", "DELETE"])
@permission_classes([IsOwnerOrReadOnly])
def user_detail(request, pk):
    user = CustomUser.objects.get(pk=pk)
    print('user', user)
    if not user:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        try:
            serializer = UserSerializer(user, context={'request': request}, many=True)
        except Exception as e:
            print("in users.views.py ", e);
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
