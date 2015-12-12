# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0002_auto_20151212_1300'),
    ]

    operations = [
        migrations.AlterField(
            model_name='servicepattern',
            name='pattern',
            field=models.CharField(help_text="A regular expression matching services. Will usually looks like '^https://some\\.server\\.com/path/.*$'.As it is a regular expression, special character must be escaped with a '\\'.", unique=True, max_length=255, verbose_name='pattern'),
            preserve_default=True,
        ),
    ]
