# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cas_server', '0004_auto_20150518_1659'),
    ]

    operations = [
        migrations.AlterField(
            model_name='filterattributvalue',
            name='attribut',
            field=models.CharField(help_text="Nom de l'attribut devant v\xe9rifier pattern", max_length=255),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='filterattributvalue',
            name='pattern',
            field=models.CharField(help_text='Une expression r\xe9guli\xe8re', max_length=255),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='replaceattributname',
            name='name',
            field=models.CharField(help_text="nom d'un attributs \xe0 transmettre au service", max_length=255),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='replaceattributname',
            name='replace',
            field=models.CharField(help_text="nom sous lequel l'attribut sera pr\xe9sent\xe9 au service. vide = inchang\xe9", max_length=255, blank=True),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='replaceattributvalue',
            name='attribut',
            field=models.CharField(help_text="Nom de l'attribut dont la valeur doit \xeatre modifi\xe9", max_length=255),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='replaceattributvalue',
            name='pattern',
            field=models.CharField(help_text='Une expression r\xe9guli\xe8re de ce qui doit \xeatre modifi\xe9', max_length=255),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='replaceattributvalue',
            name='replace',
            field=models.CharField(help_text='Par quoi le remplacer, les groupes sont captur\xe9 par \\1, \\2 \u2026', max_length=255, blank=True),
            preserve_default=True,
        ),
    ]
