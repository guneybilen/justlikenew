from django.db import models
from django.utils.text import slugify
import uuid


class Seller(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    nickname = models.CharField(max_length=100)
    email = models.EmailField()
    phone_number = models.CharField(max_length=50)
    createdAt = models.DateTimeField("Registration Date", auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)

    # def get_id(self):
    #     an_id = self.createdAt.strftime('%YYYY:%M:%d:%H:%M:%S').strip(':')
    #     print('id: ', an_id)

    def __str__(self):
        return f"{self.nickname}"




class Item(models.Model):
    brand = models.CharField("Name", max_length=240)
    model = models.CharField("Model", max_length=240)
    seller = models.ForeignKey("Seller", blank=False, null=False, related_name='items', on_delete=models.CASCADE)
    uuid_field = models.UUIDField(default=uuid.uuid4(), editable=False)
    createdAt = models.DateTimeField(auto_now_add=True)
    updatedAt = models.DateTimeField(auto_now=True)
    slug = models.SlugField(default="", null=False, blank=True, db_index=True)

    def __str__(self):
        return "{} {} by {}".format(self.brand, self.model, self.seller)

    def save(self, *args, **kwargs):
        self.slug = '-'.join((slugify(self.brand), slugify(self.model), slugify(self.seller), str(self.uuid_field)[0:8]))
        super().save(*args, **kwargs)

    print(uuid_field)