from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie, csrf_exempt
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly, IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.authentication import TokenAuthentication

from rest_framework import status
from .permissions import IsOwnerOrReadOnly
from dr import settings
from .serializers import *
from users.verify import *


@api_view(['GET'])
@permission_classes([AllowAny])
# @csrf_protect
def items_list(request):
    # print('user', request.user)
    if request.method == 'GET':
        data = Item.objects.all()
        serializer = ItemSerializer(data, context={'request': request}, many=True)

        return Response(serializer.data)


@api_view(['POST'])
@permission_classes([AllowAny])
# @csrf_protect
def items_post(request):
    if request.method == 'POST':
        # print(request.data)
        serializer = ItemSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response(status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PUT", "DELETE"])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def items_detail(request, slug):
    item = Item.objects.filter(slug=slug).first()
    # nickname = item.get_seller_nickname
    # print(request.user)
    nickname_from_client = request.data['nickname']
    result = (u'{0}'.format(item.get_seller_nickname)) == (u"{0}".format(nickname_from_client))
    if result is False:
        return Response(status=status.HTTP_401_UNAUTHORIZED)

    # print('item', item)
    if not item:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        try:
            # item_with_slug = Item.objects.filter(slug=slug).first()
            if not item:
                return Response(status=status.HTTP_404_NOT_FOUND)
            serializer = ItemSerializer(item, context={'request': request}, many=True)
        except Exception as e:
            print("in items.views.py ", e);
            return Response(status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.data)

    if request.method == 'PUT':
        item = Item.objects.filter(slug=slug).first()
        serializer = ItemSerializer(item, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
