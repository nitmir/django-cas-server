# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0007_auto_20150518_1727'),
    ]

    operations = [
        migrations.AddField(
            model_name='servicepattern',
            name='name',
            field=models.CharField(max_length=255, unique=True, null=True, blank=True),
            preserve_default=True,
        ),
    ]
