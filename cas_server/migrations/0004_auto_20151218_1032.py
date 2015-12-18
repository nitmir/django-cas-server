# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0003_auto_20151212_1721'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='servicepattern',
            options={'ordering': ('pos',), 'verbose_name': 'Service pattern', 'verbose_name_plural': 'Services patterns'},
        ),
        migrations.AlterModelOptions(
            name='user',
            options={'verbose_name': 'User', 'verbose_name_plural': 'Users'},
        ),
    ]
