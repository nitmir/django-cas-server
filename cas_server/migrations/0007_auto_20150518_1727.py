# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0006_auto_20150518_1720'),
    ]

    operations = [
        migrations.CreateModel(
            name='Usernames',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('value', models.CharField(max_length=255)),
                ('service_pattern', models.ForeignKey(related_name='usernames', to='cas_server.ServicePattern')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.RemoveField(
            model_name='servicepattern',
            name='usernames',
        ),
        migrations.AddField(
            model_name='servicepattern',
            name='restrict_users',
            field=models.BooleanField(default=False, help_text=b'Limiter les utilisateur autoris\xc3\xa9 a se connect\xc3\xa9 a ce service \xc3\xa0 celle ci-dessous'),
            preserve_default=True,
        ),
    ]
