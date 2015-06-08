# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0017_remove_user_attributs'),
    ]

    operations = [
        migrations.AddField(
            model_name='servicepattern',
            name='single_log_out_callback',
            field=models.CharField(default=b'', help_text='URL where the SLO request will be POST. empty = service url\nThis is usefull for non HTTP proxied services.', max_length=255, verbose_name='single log out callback', blank=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='replaceattributname',
            name='name',
            field=models.CharField(help_text='name of an attribut to send to the service, use * for all attributes', max_length=255, verbose_name='name'),
            preserve_default=True,
        ),
    ]
