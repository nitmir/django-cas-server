# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0003_auto_20150518_1648'),
    ]

    operations = [
        migrations.CreateModel(
            name='FilterAttributValue',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('attribut', models.CharField(max_length=255)),
                ('pattern', models.CharField(max_length=255)),
                ('service_pattern', models.ForeignKey(related_name='filters', to='cas_server.ServicePattern')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='ReplaceAttributValue',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('attribut', models.CharField(max_length=255)),
                ('pattern', models.CharField(max_length=255)),
                ('replace', models.CharField(max_length=255)),
                ('service_pattern', models.ForeignKey(related_name='replacements', to='cas_server.ServicePattern')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.RenameModel(
            old_name='Attribut',
            new_name='ReplaceAttributName',
        ),
        migrations.RemoveField(
            model_name='servicepattern',
            name='filter',
        ),
    ]
