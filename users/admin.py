from django.contrib import admin
# from django.contrib.auth import get_user_model
# from .forms import CustomUserChangeForm, CustomUserCreationForm
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser


class CustomUserAdmin(UserAdmin):
    # add_form = CustomUserCreationForm
    # form = CustomUserChangeForm
    model = CustomUser
    exclude = ('slug',)
    list_display = ('email', 'is_staff', 'is_active',)
    list_filter = ('email', 'is_staff', 'is_active',)
    fieldsets = (
        (None, {'fields': ('email', 'password', 'nickname')}),
        ('Permissions', {'fields': ('is_staff', 'is_active')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'nickname', 'password1', 'password2', 'is_staff', 'is_active')}
         ),
    )
    search_fields = ('email',)
    ordering = ('email',)


admin.site.register(CustomUser, CustomUserAdmin)
