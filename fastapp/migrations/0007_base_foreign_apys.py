# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('fastapp', '0006_apy_public'),
    ]

    operations = [
        migrations.AddField(
            model_name='base',
            name='foreign_apys',
            field=models.ManyToManyField(related_name='foreign_base', to='fastapp.Apy'),
            preserve_default=True,
        ),
    ]
