# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0019_auto_20150609_1903'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='session',
            field=models.OneToOneField(related_name='cas_server_user', null=True, on_delete=django.db.models.deletion.SET_NULL, blank=True, to='sessions.Session'),
            preserve_default=True,
        ),
    ]
