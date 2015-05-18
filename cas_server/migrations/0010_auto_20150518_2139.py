# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0009_auto_20150518_1740'),
    ]

    operations = [
        migrations.AlterField(
            model_name='replaceattributname',
            name='name',
            field=models.CharField(help_text="nom d'un attributs \xe0 transmettre au service", max_length=255),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='replaceattributname',
            unique_together=set([('name', 'service_pattern')]),
        ),
    ]
