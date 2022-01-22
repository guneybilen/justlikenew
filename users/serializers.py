from rest_framework.serializers import ModelSerializer

from .models import CustomUser


class UserSerializer(ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'email', 'nickname', 'phone_number')
