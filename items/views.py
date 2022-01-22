from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status

from .serializers import *


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticatedOrReadOnly])
def items_list(request):
    if request.method == 'GET':
        data = Item.objects.all()

        serializer = ItemSerializer(data, context={'request': request}, many=True)

        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = ItemSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticatedOrReadOnly])
def items_post(request):
    if request.method == 'GET':
        data = Item.objects.all()

        serializer = ItemSerializer(data, context={'request': request}, many=True)

        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = ItemSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', "DELETE"])
def items_detail(request, pk, slug):
    try:
        item = Item.objects.get(pk)
    except Item.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        item_with_slug = Item.objects.get(slug=slug)
        serializer = ItemSerializer(item_with_slug, context={'request': request}, many=True)

        return Response(serializer.data)

    if request.method == 'PUT':
        serializer = ItemSerializer(item, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(['GET', 'PUT', "DELETE"])
def items_detail(request, slug):
    try:
        item = Item.objects.get(slug=slug)
    except Item.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        item_with_slug = Item.objects.get(slug=slug)
        serializer = ItemSerializer(item_with_slug, context={'request': request})

        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = ItemSerializer(item, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
