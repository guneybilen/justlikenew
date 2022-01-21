# Generated by Django 4.0.1 on 2022-01-21 01:45

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('items', '0002_items'),
    ]

    operations = [
        migrations.AddField(
            model_name='item',
            name='uuid_field',
            field=models.UUIDField(default=uuid.UUID('90704922-a809-4e1e-9781-f9b53b54f445'), editable=False),
        ),
    ]
