# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('sessions', '0001_initial'),
        ('cas_server', '0018_auto_20150608_1621'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='session',
            field=models.OneToOneField(related_name='cas_server_user', null=True, blank=True, to='sessions.Session'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='user',
            name='username',
            field=models.CharField(max_length=30),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='user',
            unique_together=set([('username', 'session')]),
        ),
    ]
