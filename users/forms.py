from django import forms
from django.contrib.auth.forms import UserChangeForm, UserCreationForm

from .models import CustomUser


class CustomUserCreationForm(UserCreationForm):
    class Meta:
        models = CustomUser
        fields = ('first_name', 'last_name', 'email', 'nickname', 'phone_number')


class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = CustomUser
        fields = UserChangeForm.Meta.fields
       