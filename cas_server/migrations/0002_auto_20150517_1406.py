# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='proxygrantingticket',
            name='service_pattern',
            field=models.ForeignKey(related_name='proxygrantingticket', default=1, to='cas_server.ServicePattern'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='proxyticket',
            name='service_pattern',
            field=models.ForeignKey(related_name='proxyticket', default=1, to='cas_server.ServicePattern'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='serviceticket',
            name='service_pattern',
            field=models.ForeignKey(related_name='serviceticket', default=1, to='cas_server.ServicePattern'),
            preserve_default=False,
        ),
    ]
