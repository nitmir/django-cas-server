# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import cas_server.models
import picklefield.fields


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Proxy',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('url', models.CharField(max_length=255)),
            ],
            options={
                'ordering': ('-pk',),
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='ProxyGrantingTicket',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('attributs', picklefield.fields.PickledObjectField(editable=False)),
                ('validate', models.BooleanField(default=False)),
                ('service', models.TextField()),
                ('creation', models.DateTimeField(auto_now_add=True)),
                ('renew', models.BooleanField(default=False)),
                ('value', models.CharField(default=cas_server.models._gen_pgt, unique=True, max_length=255)),
            ],
            options={
                'abstract': False,
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='ProxyTicket',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('attributs', picklefield.fields.PickledObjectField(editable=False)),
                ('validate', models.BooleanField(default=False)),
                ('service', models.TextField()),
                ('creation', models.DateTimeField(auto_now_add=True)),
                ('renew', models.BooleanField(default=False)),
                ('value', models.CharField(default=cas_server.models._gen_pt, unique=True, max_length=255)),
            ],
            options={
                'abstract': False,
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='ServicePattern',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('pos', models.IntegerField(default=100)),
                ('pattern', models.CharField(unique=True, max_length=255)),
                ('user_field', models.CharField(default=b'', help_text=b"Nom de l'attribut transmit comme username, vide = login", max_length=255, blank=True)),
                ('usernames', models.CharField(default=b'', help_text=b"Liste d'utilisateurs accept\xc3\xa9s s\xc3\xa9par\xc3\xa9 par des virgules, vide = tous les utilisateur", max_length=255, blank=True)),
                ('attributs', models.CharField(default=b'', help_text=b"Liste des nom d'attributs \xc3\xa0 transmettre au service, s\xc3\xa9par\xc3\xa9 par une virgule. vide = aucun", max_length=255, blank=True)),
                ('proxy', models.BooleanField(default=False, help_text=b"Un ProxyGrantingTicket peut \xc3\xaatre d\xc3\xa9livr\xc3\xa9 au service pour s'authentifier en temps que l'utilisateur sur d'autres services")),
                ('filter', models.CharField(default=b'', help_text=b'Une lambda fonction pour filtrer sur les utilisateur o\xc3\xb9 leurs attribut, arg1: username, arg2:attrs_dict. vide = pas de filtre', max_length=255, blank=True)),
            ],
            options={
                'ordering': ('pos',),
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='ServiceTicket',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('attributs', picklefield.fields.PickledObjectField(editable=False)),
                ('validate', models.BooleanField(default=False)),
                ('service', models.TextField()),
                ('creation', models.DateTimeField(auto_now_add=True)),
                ('renew', models.BooleanField(default=False)),
                ('value', models.CharField(default=cas_server.models._gen_st, unique=True, max_length=255)),
            ],
            options={
                'abstract': False,
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('username', models.CharField(unique=True, max_length=30)),
                ('attributs', picklefield.fields.PickledObjectField(editable=False)),
                ('date', models.DateTimeField(auto_now=True, auto_now_add=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='serviceticket',
            name='user',
            field=models.ForeignKey(related_name='serviceticket', to='cas_server.User'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='proxyticket',
            name='user',
            field=models.ForeignKey(related_name='proxyticket', to='cas_server.User'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='proxygrantingticket',
            name='user',
            field=models.ForeignKey(related_name='proxygrantingticket', to='cas_server.User'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='proxy',
            name='proxy_ticket',
            field=models.ForeignKey(related_name='proxies', to='cas_server.ProxyTicket'),
            preserve_default=True,
        ),
    ]
