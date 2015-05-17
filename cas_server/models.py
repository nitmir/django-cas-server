# ⁻*- coding: utf-8 -*-
import default_settings

from django.conf import settings
from django.db import models
from django.contrib import messages
from picklefield.fields import PickledObjectField

import re
import os
import time
import random
import string
import requests

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
        for ticket in ServiceTicket.objects.filter(user=self):
            ticket.logout(request)
            ticket.delete()
        for ticket in ProxyTicket.objects.filter(user=self):
            ticket.logout(request)
            ticket.delete()
        for ticket in ProxyGrantingTicket.objects.filter(user=self):
            ticket.logout(request)
            ticket.delete()

    def delete(self):
        super(User, self).delete()

    def get_service_url(self, service, service_pattern, renew):
        attributs = [s.strip() for s in service_pattern.attributs.split(',')]
        ticket = ServiceTicket.objects.create(user=self, attributs = dict([(k, v) for (k, v) in self.attributs.items() if k in attributs]), service=service, renew=renew, service_pattern=service_pattern)
        ticket.save()
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
    pattern = models.CharField(max_length=255, unique=True)
    user_field = models.CharField(max_length=255, default="", blank=True, help_text="Nom de l'attribut transmit comme username, vide = login")
    usernames = models.CharField(max_length=255, default="", blank=True, help_text="Liste d'utilisateurs acceptés séparé par des virgules, vide = tous les utilisateur")
    attributs = models.CharField(max_length=255, default="", blank=True, help_text="Liste des nom d'attributs à transmettre au service, séparé par une virgule. vide = aucun")
    proxy = models.BooleanField(default=False,  help_text="Un ProxyGrantingTicket peut être délivré au service pour s'authentifier en temps que l'utilisateur sur d'autres services")
    filter = models.CharField(max_length=255, default="", blank=True, help_text="Une lambda fonction pour filtrer sur les utilisateur où leurs attribut, arg1: username, arg2:attrs_dict. vide = pas de filtre")

    def __unicode__(self):
        return u"%s: %s" % (self.pos, self.pattern)

    def check_user(self, user):
        if self.usernames and not user.username in self.usernames.split(','):
            raise BadUsername()
        if self.filter and self.filter.startswith("lambda") and not eval(str(self.filter))(user.username, user.attributs):
            raise BadFilter()
        print self.user_field
        print user.attributs.get(self.user_field)
        if self.user_field and not user.attributs.get(self.user_field):
            raise UserFieldNotDefined()
        return True


    @classmethod
    def validate(cls, service):
        for s in cls.objects.all().order_by('pos'):
            if re.match(s.pattern, service):
                return s
        raise cls.DoesNotExist()



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

    def logout(self, request):
        #if self.validate:
            xml = """<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
     ID="%(id)s" Version="2.0" IssueInstant="%(datetime)s">
    <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:NameID>
    <samlp:SessionIndex>%(ticket)s</samlp:SessionIndex>
  </samlp:LogoutRequest>""" % {'id' : os.urandom(20).encode("hex"), 'datetime' : int(time.time()), 'ticket': self.value}
            headers = {'Content-Type': 'text/xml'}
            try:
                requests.post(self.service.encode('utf-8'), data=xml.encode('utf-8'), headers=headers)
            except Exception as e:
                messages.add_message(request, messages.WARNING, u'Erreur lors de la déconnexion du service %s:\n%s' % (self.service, e))

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

