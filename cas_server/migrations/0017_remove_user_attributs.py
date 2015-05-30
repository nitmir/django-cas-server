# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0016_auto_20150528_1326'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='attributs',
        ),
    ]
