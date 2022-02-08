from rest_framework.serializers import ModelSerializer

from .models import CustomUser
import bcrypt


class UserSerializer(ModelSerializer):

    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'nickname','password', 's_name', 's_answer')
        read_only_fields = ('id', 'is_active', 'is_staff')
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'write_only': True},
            's_name': {'write_only': True},
            's_answer': {'write_only': True}
        }

    def create(self, validated_data):
        email = validated_data.get('email')
        password = validated_data.get('password')
        nickname = validated_data.get('nickname')
        str = validated_data.get('s_answer')
        s_name = validated_data.get('s_name')
        answer = b"str"
        s_answer = bcrypt.hashpw(answer, bcrypt.gensalt())
        return CustomUser.objects.create_user(email=email, password=password,
                                              nickname=nickname, s_name=s_name, s_answer=s_answer)