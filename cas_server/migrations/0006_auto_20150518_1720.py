# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0005_auto_20150518_1717'),
    ]

    operations = [
        migrations.AlterField(
            model_name='replaceattributname',
            name='name',
            field=models.CharField(help_text="nom d'un attributs \xe0 transmettre au service", unique=True, max_length=255),
            preserve_default=True,
        ),
    ]
