# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.db.models.deletion
import cas_server.utils


class Migration(migrations.Migration):

    #replaces = [(b'cas_server', '0001_initial'), (b'cas_server', '0002_auto_20150517_1406'), (b'cas_server', '0003_auto_20150518_1648'), (b'cas_server', '0004_auto_20150518_1659'), (b'cas_server', '0005_auto_20150518_1717'), (b'cas_server', '0006_auto_20150518_1720'), (b'cas_server', '0007_auto_20150518_1727'), (b'cas_server', '0008_servicepattern_name'), (b'cas_server', '0009_auto_20150518_1740'), (b'cas_server', '0010_auto_20150518_2139'), (b'cas_server', '0011_auto_20150523_1731'), (b'cas_server', '0012_auto_20150527_1956'), (b'cas_server', '0013_servicepattern_single_sign_out'), (b'cas_server', '0014_auto_20150528_0012'), (b'cas_server', '0015_auto_20150528_1202'), (b'cas_server', '0016_auto_20150528_1326'), (b'cas_server', '0017_remove_user_attributs'), (b'cas_server', '0018_auto_20150608_1621'), (b'cas_server', '0019_auto_20150609_1903'), (b'cas_server', '0020_auto_20150609_1917'), (b'cas_server', '0021_auto_20150611_2102')]

    dependencies = [
        ('sessions', '0001_initial'),
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
                ('attributs', models.TextField(blank=True, default=None, null=True)),
                ('validate', models.BooleanField(default=False)),
                ('service', models.TextField()),
                ('creation', models.DateTimeField(auto_now_add=True)),
                ('renew', models.BooleanField(default=False)),
                ('value', models.CharField(default=cas_server.utils.gen_pgt, unique=True, max_length=255)),
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
                ('attributs', models.TextField(blank=True, default=None, null=True)),
                ('validate', models.BooleanField(default=False)),
                ('service', models.TextField()),
                ('creation', models.DateTimeField(auto_now_add=True)),
                ('renew', models.BooleanField(default=False)),
                ('value', models.CharField(default=cas_server.utils.gen_pt, unique=True, max_length=255)),
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
                ('attributs', models.TextField(blank=True, default=None, null=True)),
                ('validate', models.BooleanField(default=False)),
                ('service', models.TextField()),
                ('creation', models.DateTimeField(auto_now_add=True)),
                ('renew', models.BooleanField(default=False)),
                ('value', models.CharField(default=cas_server.utils.gen_st, unique=True, max_length=255)),
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
                ('username', models.CharField(max_length=30)),
                ('date', models.DateTimeField(auto_now=True, auto_now_add=True)),
                ('session_key', models.CharField(max_length=40, null=True, blank=True)),
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
        migrations.CreateModel(
            name='ReplaceAttributName',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(help_text="nom d'un attributs \xe0 transmettre au service", max_length=255)),
                ('replace', models.CharField(help_text="nom sous lequel l'attribut sera pr\xe9sent\xe9 au service. vide = inchang\xe9", max_length=255, blank=True)),
                ('service_pattern', models.ForeignKey(related_name='attributs', to='cas_server.ServicePattern')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.RemoveField(
            model_name='servicepattern',
            name='attributs',
        ),
        migrations.CreateModel(
            name='FilterAttributValue',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('attribut', models.CharField(help_text='Name of the attribut which must verify pattern', max_length=255, verbose_name='attribut')),
                ('pattern', models.CharField(help_text='a regular expression', max_length=255, verbose_name='pattern')),
                ('service_pattern', models.ForeignKey(related_name='filters', to='cas_server.ServicePattern')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='ReplaceAttributValue',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('attribut', models.CharField(help_text='Name of the attribut for which the value must be replace', max_length=255, verbose_name='attribut')),
                ('pattern', models.CharField(help_text='An regular expression maching whats need to be replaced', max_length=255, verbose_name='pattern')),
                ('replace', models.CharField(help_text='replace expression, groups are capture by \\1, \\2 \u2026', max_length=255, verbose_name='replace', blank=True)),
                ('service_pattern', models.ForeignKey(related_name='replacements', to='cas_server.ServicePattern')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.RemoveField(
            model_name='servicepattern',
            name='filter',
        ),
        migrations.CreateModel(
            name='Username',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('value', models.CharField(help_text='username allowed to connect to the service', max_length=255, verbose_name='username')),
                ('service_pattern', models.ForeignKey(related_name='usernames', to='cas_server.ServicePattern')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.RemoveField(
            model_name='servicepattern',
            name='usernames',
        ),
        migrations.AddField(
            model_name='servicepattern',
            name='restrict_users',
            field=models.BooleanField(default=False, help_text='Limit username allowed to connect to the list provided bellow', verbose_name='restrict username'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='servicepattern',
            name='name',
            field=models.CharField(null=True, max_length=255, blank=True, help_text='A name for the service', unique=True, verbose_name='name'),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='replaceattributname',
            unique_together=set([('name', 'service_pattern')]),
        ),
        migrations.AlterUniqueTogether(
            name='replaceattributname',
            unique_together=set([('name', 'replace', 'service_pattern')]),
        ),
        migrations.AddField(
            model_name='servicepattern',
            name='single_log_out',
            field=models.BooleanField(default=False, help_text='Enable SLO for the service', verbose_name='single log out'),
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
            name='user_field',
            field=models.CharField(default=b'', help_text='Name of the attribut to transmit as username, empty = login', max_length=255, verbose_name='user field', blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='proxygrantingticket',
            name='single_log_out',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='proxyticket',
            name='single_log_out',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='serviceticket',
            name='single_log_out',
            field=models.BooleanField(default=False),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='servicepattern',
            name='proxy_callback',
            field=models.BooleanField(default=False, help_text='can be used as a proxy callback to deliver PGT', verbose_name='proxy callback'),
            preserve_default=True,
        ),
        migrations.AlterField(
            model_name='servicepattern',
            name='proxy',
            field=models.BooleanField(default=False, help_text='Proxy tickets can be delivered to the service', verbose_name='proxy'),
            preserve_default=True,
        ),
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
        migrations.AlterUniqueTogether(
            name='user',
            unique_together=set([('username', 'session_key')]),
        ),
    ]
