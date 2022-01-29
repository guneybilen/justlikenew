# Generated by Django 4.0.1 on 2022-01-29 11:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('items', '0008_alter_item_uuid_field'),
    ]

    operations = [
        migrations.AlterField(
            model_name='item',
            name='price',
            field=models.DecimalField(blank=True, decimal_places=2, default=0.0, max_digits=9, verbose_name='Price'),
        ),
    ]
