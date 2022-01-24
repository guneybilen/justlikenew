from django.contrib import admin
from items.models import Item
from django.urls import reverse


# Register your models here.

class ItemAdmin(admin.ModelAdmin):
    readonly_fields = ('slug', 'uuid_field')

    def get_absolute_url(self):
        return reverse('item-detail', kwargs={'slug': self.slug})


admin.site.register(Item, ItemAdmin)
