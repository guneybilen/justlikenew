from rest_framework.serializers import ModelSerializer

from .models import CustomUser
import sha512_crypt


class UserSerializer(ModelSerializer):

    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'is_active', 'nickname','password', 's_name', 's_answer')
        read_only_fields = ('id', 'is_active', 'is_staff')
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'write_only': True},
            's_name': {'write_only': True},
            's_answer': {'write_only': True},
        }

    def create(self, validated_data):
        email = validated_data.get('email')
        password = validated_data.get('password')
        nickname = validated_data.get('nickname')
        str = validated_data.get('s_answer')
        s_name = validated_data.get('s_name')

        hashed = sha512_crypt.encrypt(str)

        return CustomUser.objects.create_user(email=email, password=password,
                                              nickname=nickname, s_name=s_name,
                                              s_answer=hashed)

    def update(self, instance, validated_data):
        # instance.brand = validated_data.get('brand', instance.brand)
        # instance.model = validated_data.get('model', instance.model)
        # instance.price = validated_data.get('price', instance.price)
        # instance.entry = validated_data.get('entry', instance.entry)
        # instance.item_image1 = validated_data.get('item_image1', instance.item_image1)
        # instance.item_image2 = validated_data.get('item_image2', instance.item_image2)
        # instance.item_image3 = validated_data.get('item_image3', instance.item_image3)
        # instance.seller = validated_data.get('seller', instance.seller)
        return super().update(instance, validated_data)