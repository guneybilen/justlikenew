from rest_framework import serializers
from .models import Item


class ItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = Item
        # slug_field = 'slug'
        fields = ('brand', 'model', 'seller', 'price', 'entry', 'createdAt', 'slug')

