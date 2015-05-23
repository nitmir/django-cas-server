# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0010_auto_20150518_2139'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='replaceattributname',
            unique_together=set([('name', 'replace', 'service_pattern')]),
        ),
    ]
