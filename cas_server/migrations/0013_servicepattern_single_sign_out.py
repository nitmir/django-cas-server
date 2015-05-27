# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0012_auto_20150527_1956'),
    ]

    operations = [
        migrations.AddField(
            model_name='servicepattern',
            name='single_sign_out',
            field=models.BooleanField(default=False, help_text=b'Activer le SSO sur le service'),
            preserve_default=True,
        ),
    ]
