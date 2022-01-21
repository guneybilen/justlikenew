from django.contrib import admin
from items.models import Item, Seller


# Register your models here.

class ItemAdmin(admin.ModelAdmin):
    readonly_fields = ('slug',)


admin.site.register(Item, ItemAdmin)
admin.site.register(Seller)
