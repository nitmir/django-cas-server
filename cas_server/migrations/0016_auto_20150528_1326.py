# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0015_auto_20150528_1202'),
    ]

    operations = [
        migrations.AddField(
            model_name='servicepattern',
            name='proxy_callback',
            field=models.BooleanField(default=False, help_text='can be used as a proxy callback to deliver PGT', verbose_name='proxy callback'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='servicepattern',
            name='proxy',
            field=models.BooleanField(default=False, help_text='Proxy tickets can be delivered to the service', verbose_name='proxy'),
            preserve_default=True,
        ),
    ]
