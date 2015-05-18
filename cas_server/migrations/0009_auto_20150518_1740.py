# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0008_servicepattern_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='servicepattern',
            name='name',
            field=models.CharField(help_text=b'Un nom pour le service', max_length=255, unique=True, null=True, blank=True),
            preserve_default=True,
        ),
    ]
