# ⁻*- coding: utf-8 -*-
import default_settings

from django.conf import settings
from django.db import models
from django.contrib import messages
from picklefield.fields import PickledObjectField
from django.utils.translation import ugettext as _

import re
import os
import time
import random
import string

from concurrent.futures import ThreadPoolExecutor
from requests_futures.sessions import FuturesSession

import utils
def _gen_ticket(prefix):
    return '%s-%s' % (prefix, ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(settings.CAS_ST_LEN)))

def _gen_st():
    return _gen_ticket('ST')

def _gen_pt():
    return _gen_ticket('PT')

def _gen_pgt():
    return _gen_ticket('PGT')


class User(models.Model):
    username = models.CharField(max_length=30, unique=True)
    attributs = PickledObjectField()
    date = models.DateTimeField(auto_now_add=True, auto_now=True)

    def __unicode__(self):
        return self.username

    def logout(self, request):
        async_list = []
        session = FuturesSession(executor=ThreadPoolExecutor(max_workers=10))
        for ticket in ServiceTicket.objects.filter(user=self):
            async_list.append(ticket.logout(request, session))
            ticket.delete()
        for ticket in ProxyTicket.objects.filter(user=self):
            async_list.append(ticket.logout(request, session))
            ticket.delete()
        for ticket in ProxyGrantingTicket.objects.filter(user=self):
            async_list.append(ticket.logout(request, session))
            ticket.delete()
        for future in async_list:
            try:
                future.result()
            except Exception as e:
                messages.add_message(request, messages.WARNING, _(u'Error during service logout %s') % e)

    def delete(self):
        super(User, self).delete()


    def get_ticket(self, TicketClass, service, service_pattern, renew): 
        attributs = dict((a.name, a.replace if a.replace else a.name) for a in service_pattern.attributs.all())
        replacements = dict((a.name, (a.pattern, a.replace)) for a in service_pattern.replacements.all())
        service_attributs = {}
        for (k,v) in self.attributs.items():
            if k in attributs:
                if k in replacements:
                    v = re.sub(replacements[k][0], replacements[k][1], v)
                service_attributs[attributs[k]] = v
        ticket = TicketClass.objects.create(user=self, attributs = service_attributs, service=service, renew=renew, service_pattern=service_pattern)
        ticket.save()
        return ticket

    def get_service_url(self, service, service_pattern, renew):
        ticket = self.get_ticket(ServiceTicket, service, service_pattern, renew)
        url = utils.update_url(service, {'ticket':ticket.value})
        return url

class BadUsername(Exception):
    pass
class BadFilter(Exception):
    pass
class UserFieldNotDefined(Exception):
    pass
class ServicePattern(models.Model):
    class Meta:
        ordering = ("pos", )

    pos = models.IntegerField(default=100)
    name = models.CharField(max_length=255, unique=True, blank=True, null=True, help_text="Un nom pour le service")
    pattern = models.CharField(max_length=255, unique=True)
    user_field = models.CharField(max_length=255, default="", blank=True, help_text="Nom de l'attribut transmit comme username, vide = login")
    #usernames = models.CharField(max_length=255, default="", blank=True, help_text="Liste d'utilisateurs acceptés séparé par des virgules, vide = tous les utilisateur")
    #attributs = models.CharField(max_length=255, default="", blank=True, help_text="Liste des nom d'attributs à transmettre au service, séparé par une virgule. vide = aucun")
    restrict_users = models.BooleanField(default=False, help_text="Limiter les utilisateur autorisé a se connecté a ce service à celle ci-dessous")
    proxy = models.BooleanField(default=False,  help_text="Un ProxyGrantingTicket peut être délivré au service pour s'authentifier en temps que l'utilisateur sur d'autres services")
    #filter = models.CharField(max_length=255, default="", blank=True, help_text="Une lambda fonction pour filtrer sur les utilisateur où leurs attribut, arg1: username, arg2:attrs_dict. vide = pas de filtre")

    def __unicode__(self):
        return u"%s: %s" % (self.pos, self.pattern)

    def check_user(self, user):
        if self.restrict_users and not self.usernames.filter(value=user.username):
            raise BadUsername()
        for f in self.filters.all():
            if isinstance(user.attributs[f.attribut], list):
                l = user.attributs[f.attribut]
            else:
                l = [user.attributs[f.attribut]]
            for v in l:
                if re.match(f.pattern, str(v)):
                    break
            else:
                raise BadFilter('%s do not match %s %s' % (f.pattern, f.attribut, user.attributs[f.attribut]) )
        if self.user_field and not user.attributs.get(self.user_field):
            raise UserFieldNotDefined()
        return True


    @classmethod
    def validate(cls, service):
        for s in cls.objects.all().order_by('pos'):
            if re.match(s.pattern, service):
                return s
        raise cls.DoesNotExist()

class Usernames(models.Model):
    value = models.CharField(max_length=255)
    service_pattern = models.ForeignKey(ServicePattern, related_name="usernames")

class ReplaceAttributName(models.Model):
    class Meta:
        unique_together = ('name', 'service_pattern')
    name = models.CharField(max_length=255, help_text=u"nom d'un attributs à transmettre au service")
    replace = models.CharField(max_length=255, blank=True, help_text=u"nom sous lequel l'attribut sera présenté au service. vide = inchangé")
    service_pattern = models.ForeignKey(ServicePattern, related_name="attributs")

    def __unicode__(self):
        if not self.replace:
            return self.name
        else:
            return u"%s → %s" % (self.name, self.replace)

class FilterAttributValue(models.Model):
    attribut = models.CharField(max_length=255, help_text=u"Nom de l'attribut devant vérifier pattern")
    pattern = models.CharField(max_length=255, help_text=u"Une expression régulière")
    service_pattern = models.ForeignKey(ServicePattern, related_name="filters")

    def __unicode__(self):
        return u"%s %s" % (self.attribut, self.pattern)

class ReplaceAttributValue(models.Model):
    attribut = models.CharField(max_length=255, help_text=u"Nom de l'attribut dont la valeur doit être modifié")
    pattern = models.CharField(max_length=255, help_text=u"Une expression régulière de ce qui doit être modifié")
    replace = models.CharField(max_length=255, blank=True, help_text=u"Par quoi le remplacer, les groupes sont capturé par \\1, \\2 …")
    service_pattern = models.ForeignKey(ServicePattern, related_name="replacements")

    def __unicode__(self):
        return u"%s %s %s" % (self.attribut, self.pattern, self.replace)


class Ticket(models.Model):
    class Meta:
        abstract = True
    user = models.ForeignKey(User, related_name="%(class)s")
    attributs = PickledObjectField()
    validate = models.BooleanField(default=False)
    service = models.TextField()
    service_pattern = models.ForeignKey(ServicePattern, related_name="%(class)s") 
    creation = models.DateTimeField(auto_now_add=True)
    renew = models.BooleanField(default=False)

    def __unicode__(self):
        return u"%s: %s %s" % (self.user, self.value, self.service)

    def logout(self, request, session):
        #if self.validate:
            xml = """<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
     ID="%(id)s" Version="2.0" IssueInstant="%(datetime)s">
    <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:NameID>
    <samlp:SessionIndex>%(ticket)s</samlp:SessionIndex>
  </samlp:LogoutRequest>""" % {'id' : os.urandom(20).encode("hex"), 'datetime' : int(time.time()), 'ticket': self.value}
            headers = {'Content-Type': 'text/xml'}
            try:
                return session.post(self.service.encode('utf-8'), data=xml.encode('utf-8'), headers=headers)
            except Exception as e:
                messages.add_message(request, messages.WARNING, _(u'Error during service logout %(service)s:\n%(error)s') % {'service': self.service, 'error':e})

class ServiceTicket(Ticket):
    value = models.CharField(max_length=255, default=_gen_st, unique=True)
class ProxyTicket(Ticket):
    value = models.CharField(max_length=255, default=_gen_pt, unique=True)
class ProxyGrantingTicket(Ticket):
    value = models.CharField(max_length=255, default=_gen_pgt, unique=True)
#class ProxyGrantingTicketIOU(Ticket):
#    value = models.CharField(max_length=255, default=lambda:_gen_ticket('PGTIOU'), unique=True)

class Proxy(models.Model):
    class Meta:
        ordering = ("-pk", )
    url = models.CharField(max_length=255)
    proxy_ticket = models.ForeignKey(ProxyTicket, related_name="proxies")

