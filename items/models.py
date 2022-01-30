from django.db import models
from django.utils.text import slugify
from django.urls import reverse
from users.models import CustomUser
from django.utils.translation import gettext_lazy as _

import uuid


class Item(models.Model):
    brand = models.CharField(_("Name"), max_length=240)
    model = models.CharField(_("Model"), max_length=240)
    seller = models.ForeignKey(CustomUser, blank=False, null=False, related_name='items', on_delete=models.CASCADE)
    price = models.DecimalField(_("Price"), default='', blank=True, null=True, max_digits=9, decimal_places=2)
    entry = models.TextField(_("Entry"), max_length=1000, blank=True, default='', null=False)
    uuid_field = models.UUIDField()
    createdAt = models.DateTimeField(_("Item Listing Date"), auto_now_add=True)
    updatedAt = models.DateTimeField(_("Item Updated at"), auto_now=True)
    slug = models.SlugField("Slug", null=False, blank=True, db_index=True, unique=True)
    item_image1 = models.ImageField(default="", null=True, blank=True, upload_to='images/')
    item_image2 = models.ImageField(default="", null=True, blank=True, upload_to='images/')
    item_image3 = models.ImageField(default="", null=True, blank=True, upload_to='images/')

    def __str__(self):
        return "{} {} by {}".format(self.brand, self.model, self.seller)

    @property
    def get_seller_nickname(self):
        return f"{self.seller}"

    @property
    def get_user_id(self):
        return self.seller.id


    # Relegated the followings to serializers.
    # def __init__(self, *args, **kwargs):
    #     super(Item, self).__init__(*args, **kwargs)
    #     self.__original_brand = self.brand
    #     self.__original_model = self.model
    #     self.__original_price = self.price
    #     self.__original_entry = self.entry
    #
    # def clean(self, *args, **kwargs):
    #     if self.__original_brand == self.brand and self.__original_model == self.model and self.__original_price == self.price and self.__original_entry == self.entry:
    #         return None
    #     else:
    #         return True

    def save(self, *args, **kwargs):
        # result = self.full_clean()
        # print(result)
        # if result is not None:
        #     self.uuid_field = uuid.uuid4()
        self.slug = '-'.join(
            (slugify(self.seller), str(self.uuid_field)[0:16]))
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse('item-detail', kwargs={'slug': self.slug})

    class Meta:
        ordering = ['createdAt']
