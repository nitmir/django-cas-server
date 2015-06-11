# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0020_auto_20150609_1917'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='session_key',
            field=models.CharField(max_length=40, null=True, blank=True),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='user',
            unique_together=set([('username', 'session_key')]),
        ),
        migrations.RemoveField(
            model_name='user',
            name='session',
        ),
    ]
