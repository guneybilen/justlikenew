import uuid

from rest_framework import serializers
from .models import Item
from .models import CustomUser


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('nickname')
        # read_only_fields = ('is_active', 'is_staff')

    def to_representation(self, value):
        return value.nickname


class ItemSerializer(serializers.ModelSerializer):
    # user = UserSerializer(source='seller', read_only=True)

    # get_nickname = serializers.SerializerMethodField()
    #
    # def get_nickname(self, obj):
    #     return obj.get_seller_nickname()


    def create(self, validated_data):
        uuid_field = uuid.uuid4()
        return Item.objects.create(uuid_field=uuid_field, **validated_data)

    def update(self, instance, validated_data):
        instance.brand = validated_data.get('brand', instance.brand)
        instance.model = validated_data.get('model', instance.model)
        instance.price = validated_data.get('price', instance.price)
        instance.entry = validated_data.get('entry', instance.entry)
        # instance.seller = validated_data.get('seller', instance.seller)
        return super().update(instance, validated_data)

    class Meta:
        model = Item
        fields = ('brand', 'model', 'seller', 'price', 'entry', 'createdAt', 'slug', 'get_user_id', 'get_seller_nickname')
