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
    price = models.DecimalField(_("Price"), default=0.00, max_digits=9, decimal_places=2)
    entry = models.TextField(_("Entry"), max_length=1000, blank=True, default='', null=False)
    uuid_field = models.UUIDField(default=uuid.uuid4(), editable=False)
    createdAt = models.DateTimeField(_("Item Listing Date"), auto_now_add=True)
    updatedAt = models.DateTimeField(_("Item Updated at"), auto_now=True)
    slug = models.SlugField("Slug", default="", null=False, blank=True, db_index=True)

    def __str__(self):
        return "{} {} by {}".format(self.brand, self.model, self.seller)

    def save(self, *args, **kwargs):
        self.slug = '-'.join(
            (slugify(self.brand), slugify(self.model), slugify(self.seller), str(self.uuid_field)[0:8]))
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse('item-detail', kwargs={'slug': self.slug})

    class Meta:
        ordering = ['-createdAt']