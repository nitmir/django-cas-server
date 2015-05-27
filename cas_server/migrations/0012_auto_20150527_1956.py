# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0011_auto_20150523_1731'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Usernames',
            new_name='Username',
        ),
    ]
