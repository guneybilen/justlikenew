# users/models.py
# from django.contrib.auth.models import AbstractUser
# from django.db import models
# from django.contrib.auth.hashers import make_password
from django.contrib.auth.base_user import BaseUserManager
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _


class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """

    def create_user(self, email, password, nickname, **extra_fields):
        print("user created...")
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError(_('the email must be set'))

        if not nickname:
            raise ValueError(_('the nickname must be set'))

        email = self.normalize_email(email)
        user = self.model(email=email, nickname=nickname, **extra_fields)
        # print("!!!!!!!!!!!!!!!!!!!!!!!!!!", password)
        # DO NOT USE make_password() serializers.Userserializer crate method takes care of hashing password
        # user.set_password(make_password(password))
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password, nickname, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """

        print("superuser created")
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, nickname, **extra_fields)


class CustomUser(AbstractUser):
    username = None
    first_name = models.CharField(_("First Name"), max_length=100)
    last_name = models.CharField(_("Last Name"), max_length=100)
    nickname = models.CharField(_("Nickname"), max_length=100, unique=True)
    email = models.EmailField(_("Email"), unique=True)
    phone_number = models.CharField(_("Phone Number"), max_length=50)
    createdAt = models.DateTimeField(_("Registration Date"), auto_now_add=True)
    updatedAt = models.DateTimeField(_("Updated at"), auto_now=True)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['nickname']

    objects = CustomUserManager()

    def __str__(self):
        return f"{self.nickname}"
