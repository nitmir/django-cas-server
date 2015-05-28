# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0014_auto_20150528_0012'),
    ]

    operations = [
        migrations.AddField(
            model_name='proxygrantingticket',
            name='single_log_out',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='proxyticket',
            name='single_log_out',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='serviceticket',
            name='single_log_out',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
    ]
