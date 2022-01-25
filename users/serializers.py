from rest_framework.serializers import ModelSerializer

from .models import CustomUser


class UserSerializer(ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('id', 'nickname',)

    def create(self, validated_data):
        return CustomUser.objects.create_user(**validated_data)