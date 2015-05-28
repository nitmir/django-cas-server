# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0013_servicepattern_single_sign_out'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='servicepattern',
            name='single_sign_out',
        ),
        migrations.AddField(
            model_name='servicepattern',
            name='single_log_out',
            field=models.BooleanField(default=False, help_text='Enable SLO for the service', verbose_name='single log out'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='filterattributvalue',
            name='attribut',
            field=models.CharField(help_text='Name of the attribut which must verify pattern', max_length=255, verbose_name='attribut'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='filterattributvalue',
            name='pattern',
            field=models.CharField(help_text='a regular expression', max_length=255, verbose_name='pattern'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='replaceattributname',
            name='name',
            field=models.CharField(help_text='name of an attribut to send to the service', max_length=255, verbose_name='name'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='replaceattributname',
            name='replace',
            field=models.CharField(help_text='name under which the attribut will be showto the service. empty = default name of the attribut', max_length=255, verbose_name='replace', blank=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='replaceattributvalue',
            name='attribut',
            field=models.CharField(help_text='Name of the attribut for which the value must be replace', max_length=255, verbose_name='attribut'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='replaceattributvalue',
            name='pattern',
            field=models.CharField(help_text='An regular expression maching whats need to be replaced', max_length=255, verbose_name='pattern'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='replaceattributvalue',
            name='replace',
            field=models.CharField(help_text='replace expression, groups are capture by \\1, \\2 \u2026', max_length=255, verbose_name='replace', blank=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='servicepattern',
            name='name',
            field=models.CharField(null=True, max_length=255, blank=True, help_text='A name for the service', unique=True, verbose_name='name'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='servicepattern',
            name='pattern',
            field=models.CharField(unique=True, max_length=255, verbose_name='pattern'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='servicepattern',
            name='pos',
            field=models.IntegerField(default=100, verbose_name='position'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='servicepattern',
            name='proxy',
            field=models.BooleanField(default=False, help_text='A ProxyGrantingTicket can be delivered to the service in order to authenticate for the user on a backend service', verbose_name='proxy'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='servicepattern',
            name='restrict_users',
            field=models.BooleanField(default=False, help_text='Limit username allowed to connect to the list provided bellow', verbose_name='restrict username'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='servicepattern',
            name='user_field',
            field=models.CharField(default=b'', help_text='Name of the attribut to transmit as username, empty = login', max_length=255, verbose_name='user field', blank=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='username',
            name='value',
            field=models.CharField(help_text='username allowed to connect to the service', max_length=255, verbose_name='username'),
            preserve_default=True,
        ),
    ]
