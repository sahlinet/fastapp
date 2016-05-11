# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('fastapp', '0014_apy_everyone'),
    ]

    operations = [
        migrations.AddField(
            model_name='base',
            name='static_public',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
    ]
