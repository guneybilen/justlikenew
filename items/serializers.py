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
    #
    # get_nickname = serializers.SerializerMethodField()
    #
    # def get_nickname(self, obj):
    #     return obj.get_seller_nickname()

    price = serializers.DecimalField(required=False, max_digits=9, decimal_places=2)
    item_image1 = serializers.ImageField(required=False, allow_null=True, default='')
    item_image2 = serializers.ImageField(required=False, allow_null=True, default='')
    item_image3 = serializers.ImageField(required=False, allow_null=True, default='')

    def create(self, validated_data):
        uuid_field = uuid.uuid4()
        return Item.objects.create(uuid_field=uuid_field, **validated_data)

    def update(self, instance, validated_data):
        instance.brand = validated_data.get('brand', instance.brand)
        instance.model = validated_data.get('model', instance.model)
        instance.price = validated_data.get('price', instance.price)
        instance.entry = validated_data.get('entry', instance.entry)
        instance.item_image1 = validated_data.get('item_image1', instance.item_image1)
        instance.item_image2 = validated_data.get('item_image2', instance.item_image2)
        instance.item_image3 = validated_data.get('item_image3', instance.item_image3)
        # instance.seller = validated_data.get('seller', instance.seller)
        return super().update(instance, validated_data)

    class Meta:
        model = Item
        fields = (
            'brand', 'model', 'seller', 'item_image1', 'item_image2', 'item_image3', 'price', 'entry', 'createdAt',
            'slug',
            'get_user_id', 'get_seller_nickname')
        # extra_kwargs = {
        #     'price': {'required': False, 'allow_null': True, 'default': ''},
        #     'item_image1': {'required': False, 'allow_null': True, 'default': ''},
        #     'item_image2': {'required': False, 'allow_null': True, 'default': ''},
        #     'item_image3': {'required': False, 'allow_null': True, 'default': ''}
        # }
