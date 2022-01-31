from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie, csrf_exempt
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly, IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.authentication import TokenAuthentication

from rest_framework import status
from .permissions import IsOwnerOrReadOnly
from dr import settings
from .serializers import *
from users.verify import *

def clear_nulls(request):
    if request.data['item_image1'] == 'null':
        request.data["item_image1"] = ""
    if request.data['item_image2'] == 'null':
        request.data["item_image2"] = ""
    if request.data['item_image3'] == 'null':
        request.data["item_image3"] = ""
    return request

@api_view(['GET'])
@authentication_classes([])
@permission_classes([])
@csrf_protect
def items_list(request):
    # print('user', request.user)
    if request.method == 'GET':
        data = Item.objects.all()
        serializer = ItemSerializer(data, context={'request': request}, many=True)

        return Response(serializer.data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@ensure_csrf_cookie
def items_post(request):
    if request.method == 'POST' and request.user is not AnonymousUser:
        if request.user.is_active == False:
            return Response(status.HTTP_404_NOT_FOUND)
        # if request.data['item_image1'] == 'null':
        #     request.data["item_image1"] = ""
        # if request.data['item_image2'] == 'null':
        #     request.data["item_image2"] = ""
        # if request.data['item_image3'] == 'null':
        #     request.data["item_image3"] = ""
        # if request.data['price'] == '':
        #     request.data["price"] = 0
        serializer = ItemSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    return Response(status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PUT", "DELETE"])
@permission_classes([IsAuthenticatedOrReadOnly])
@ensure_csrf_cookie
def items_detail(request, slug):
    # print(request.data)
    item = Item.objects.filter(slug=slug).first()
    nickname_from_client = request.data['nickname']
    result = (u'{0}'.format(item.get_seller_nickname)) == (u"{0}".format(nickname_from_client))
    if result is False:
        return Response(status=status.HTTP_401_UNAUTHORIZED)

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
        # if request.data['item_image1'] == 'null':
        #     request.data["item_image1"] = ""
        # if request.data['item_image2'] == 'null':
        #     request.data["item_image2"] = ""
        # if request.data['item_image3'] == 'null':
        #     request.data["item_image3"] = ""
        # if request.data['price'] == '':
        #     request.data["price"] = 0
        # cleared_data = clear_nulls(request)
        item = Item.objects.filter(slug=slug).first()
        serializer = ItemSerializer(item, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()

            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
