# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0002_auto_20150517_1406'),
    ]

    operations = [
        migrations.CreateModel(
            name='Attribut',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=255)),
                ('replace', models.CharField(default=b'', max_length=255, blank=True)),
                ('service_pattern', models.ForeignKey(related_name='attributs', to='cas_server.ServicePattern')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.RemoveField(
            model_name='servicepattern',
            name='attributs',
        ),
    ]
