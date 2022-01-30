# Generated by Django 4.0.1 on 2022-01-30 16:44

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Item',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('brand', models.CharField(max_length=240, verbose_name='Name')),
                ('model', models.CharField(max_length=240, verbose_name='Model')),
                ('price', models.DecimalField(blank=True, decimal_places=2, default='', max_digits=9, null=True, verbose_name='Price')),
                ('entry', models.TextField(blank=True, default='', max_length=1000, verbose_name='Entry')),
                ('uuid_field', models.UUIDField()),
                ('createdAt', models.DateTimeField(auto_now_add=True, verbose_name='Item Listing Date')),
                ('updatedAt', models.DateTimeField(auto_now=True, verbose_name='Item Updated at')),
                ('slug', models.SlugField(blank=True, unique=True, verbose_name='Slug')),
                ('item_image1', models.ImageField(blank=True, default='', null=True, upload_to='images/')),
                ('item_image2', models.ImageField(blank=True, default='', null=True, upload_to='images/')),
                ('item_image3', models.ImageField(blank=True, default='', null=True, upload_to='images/')),
            ],
            options={
                'ordering': ['createdAt'],
            },
        ),
    ]
