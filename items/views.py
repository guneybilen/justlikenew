from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from .permissions import IsOwnerOrReadOnly

from .serializers import *


@api_view(['GET', 'POST'])
@permission_classes([IsOwnerOrReadOnly])
def items_list(request):

    if request.method == 'GET':
        data = Item.objects.all()

        serializer = ItemSerializer(data, context={'request': request}, many=True)

        return Response(serializer.data)

    elif request.method == 'POST':
        print(request.data)

        serializer = ItemSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET", "PUT", "DELETE"])
@permission_classes([IsOwnerOrReadOnly])
def items_detail(request, slug):
    item = Item.objects.filter(slug=slug).first()
    print('item', item)
    if not item:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        try:
            item_with_slug = Item.objects.filter(slug=slug)
            if not item_with_slug:
                return Response(status=status.HTTP_404_NOT_FOUND)
            serializer = ItemSerializer(item_with_slug, context={'request': request}, many=True)
        except Exception as e:
            print("in items.views.py ", e);
            return Response(status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.data)

    if request.method == 'PUT':
        serializer = ItemSerializer(item, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
