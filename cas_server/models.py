# ⁻*- coding: utf-8 -*-
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License version 3 for
# more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (c) 2015 Valentin Samir
"""models for the app"""
from . import default_settings

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

from . import utils

def _gen_ticket(prefix):
    """Generate a ticket with prefix `prefix`"""
    return '%s-%s' % (
        prefix,
        ''.join(
            random.choice(
                string.ascii_letters + string.digits
            ) for _ in range(settings.CAS_ST_LEN)
        )
    )

def _gen_st():
    """Generate a Service Ticket"""
    return _gen_ticket('ST')

def _gen_pt():
    """Generate a Proxy Ticket"""
    return _gen_ticket('PT')

def _gen_pgt():
    """Generate a Proxy Granting Ticket"""
    return _gen_ticket('PGT')

def gen_pgtiou():
    """Generate a Proxy Granting Ticket IOU"""
    return _gen_ticket('PGTIOU')

class User(models.Model):
    """A user logged into the CAS"""
    username = models.CharField(max_length=30, unique=True)
    attributs = PickledObjectField()
    date = models.DateTimeField(auto_now_add=True, auto_now=True)

    def __unicode__(self):
        return self.username

    def logout(self, request):
        """Sending SSO request to all services the user logged in"""
        async_list = []
        session = FuturesSession(executor=ThreadPoolExecutor(max_workers=10))
        for ticket in ServiceTicket.objects.filter(user=self, validate=True):
            async_list.append(ticket.logout(request, session))
            ticket.delete()
        for ticket in ProxyTicket.objects.filter(user=self, validate=True):
            async_list.append(ticket.logout(request, session))
            ticket.delete()
        for ticket in ProxyGrantingTicket.objects.filter(user=self, validate=True):
            async_list.append(ticket.logout(request, session))
            ticket.delete()
        for future in async_list:
            if future:
                try:
                    future.result()
                except Exception as error:
                    messages.add_message(
                        request,
                        messages.WARNING,
                        _(u'Error during service logout %r') % error
                    )

    def get_ticket(self, ticket_class, service, service_pattern, renew):
        """
           Generate a ticket using `ticket_class` for the service
           `service` matching `service_pattern` and asking or not for
           authentication renewal with `renew
        """
        attributs = dict(
            (a.name, a.replace if a.replace else a.name) for a in service_pattern.attributs.all()
        )
        replacements = dict(
            (a.name, (a.pattern, a.replace)) for a in service_pattern.replacements.all()
        )
        service_attributs = {}
        for (key, value) in self.attributs.items():
            if key in attributs:
                if key in replacements:
                    value = re.sub(replacements[key][0], replacements[key][1], value)
                service_attributs[attributs[key]] = value
        ticket = ticket_class.objects.create(
            user=self,
            attributs=service_attributs,
            service=service,
            renew=renew,
            service_pattern=service_pattern
        )
        ticket.save()
        return ticket

    def get_service_url(self, service, service_pattern, renew):
        """Return the url to which the user must be redirected to
        after a Service Ticket has been generated"""
        ticket = self.get_ticket(ServiceTicket, service, service_pattern, renew)
        url = utils.update_url(service, {'ticket':ticket.value})
        return url

class BadUsername(Exception):
    """Exception raised then an non allowed username
    try to get a ticket for a service"""
    pass
class BadFilter(Exception):
    """"Exception raised then a user try
    to get a ticket for a service and do not reach a condition"""
    pass

class UserFieldNotDefined(Exception):
    """Exception raised then a user try to get a ticket for a service
    using as username an attribut not present on this user"""
    pass
class ServicePattern(models.Model):
    """Allowed services pattern agains services are tested to"""
    class Meta:
        ordering = ("pos", )

    pos = models.IntegerField(default=100)
    name = models.CharField(
        max_length=255,
        unique=True,
        blank=True,
        null=True,
        help_text="Un nom pour le service"
    )
    pattern = models.CharField(max_length=255, unique=True)
    user_field = models.CharField(
        max_length=255,
        default="",
        blank=True,
        help_text="Nom de l'attribut transmit comme username, vide = login"
    )
    restrict_users = models.BooleanField(
        default=False,
        help_text="Limiter les utilisateur autorisé a se connecté a ce service à celle ci-dessous"
    )
    proxy = models.BooleanField(
        default=False,
        help_text="Un ProxyGrantingTicket peut être délivré au service pour " \
        "s'authentifier en temps que l'utilisateur sur d'autres services"
    )
    single_sign_out = models.BooleanField(
        default=False,
        help_text="Activer le SSO sur le service"
    )

    def __unicode__(self):
        return u"%s: %s" % (self.pos, self.pattern)

    def check_user(self, user):
        """Check if `user` if allowed to use theses services"""
        if self.restrict_users and not self.usernames.filter(value=user.username):
            raise BadUsername()
        for filtre in self.filters.all():
            if isinstance(user.attributs[filtre.attribut], list):
                attrs = user.attributs[filtre.attribut]
            else:
                attrs = [user.attributs[filtre.attribut]]
            for value in attrs:
                if re.match(filtre.pattern, str(value)):
                    break
            else:
                raise BadFilter('%s do not match %s %s' % (
                    filtre.pattern,
                    filtre.attribut,
                    user.attributs[filtre.attribut]
                ))
        if self.user_field and not user.attributs.get(self.user_field):
            raise UserFieldNotDefined()
        return True


    @classmethod
    def validate(cls, service):
        """Check if a Service Patern match `service` and
        return it, else raise `ServicePattern.DoesNotExist`"""
        for service_pattern in cls.objects.all().order_by('pos'):
            if re.match(service_pattern.pattern, service):
                return service_pattern
        raise cls.DoesNotExist()

class Username(models.Model):
    """A list of allowed usernames on a service pattern"""
    value = models.CharField(max_length=255)
    service_pattern = models.ForeignKey(ServicePattern, related_name="usernames")

    def __unicode__(self):
        return self.value

class ReplaceAttributName(models.Model):
    """A list of replacement of attributs name for a service pattern"""
    class Meta:
        unique_together = ('name', 'replace', 'service_pattern')
    name = models.CharField(
        max_length=255,
        help_text=u"nom d'un attributs à transmettre au service"
    )
    replace = models.CharField(
        max_length=255,
        blank=True,
        help_text=u"nom sous lequel l'attribut sera présenté " \
        u"au service. vide = inchangé"
    )
    service_pattern = models.ForeignKey(ServicePattern, related_name="attributs")

    def __unicode__(self):
        if not self.replace:
            return self.name
        else:
            return u"%s → %s" % (self.name, self.replace)

class FilterAttributValue(models.Model):
    """A list of filter on attributs for a service pattern"""
    attribut = models.CharField(
        max_length=255,
        help_text=u"Nom de l'attribut devant vérifier pattern"
    )
    pattern = models.CharField(
        max_length=255,
        help_text=u"Une expression régulière"
    )
    service_pattern = models.ForeignKey(ServicePattern, related_name="filters")

    def __unicode__(self):
        return u"%s %s" % (self.attribut, self.pattern)

class ReplaceAttributValue(models.Model):
    """Replacement to apply on attributs values for a service pattern"""
    attribut = models.CharField(
        max_length=255,
        help_text=u"Nom de l'attribut dont la valeur doit être modifié"
    )
    pattern = models.CharField(
        max_length=255,
        help_text=u"Une expression régulière de ce qui doit être modifié"
    )
    replace = models.CharField(
        max_length=255,
        blank=True,
        help_text=u"Par quoi le remplacer, les groupes sont capturé par \\1, \\2 …"
    )
    service_pattern = models.ForeignKey(ServicePattern, related_name="replacements")

    def __unicode__(self):
        return u"%s %s %s" % (self.attribut, self.pattern, self.replace)


class Ticket(models.Model):
    """Generic class for a Ticket"""
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
        return u"Ticket(%s, %s)" % (self.user, self.service)

    def logout(self, request, session):
        """Send a SSO request to the ticket service"""
        if self.validate and self.service_pattern.single_sign_out:
            xml = """<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
     ID="%(id)s" Version="2.0" IssueInstant="%(datetime)s">
    <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:NameID>
    <samlp:SessionIndex>%(ticket)s</samlp:SessionIndex>
  </samlp:LogoutRequest>""" % \
            {
                'id' : os.urandom(20).encode("hex"),
                'datetime' : int(time.time()),
                'ticket': self.value
            }
            headers = {'Content-Type': 'text/xml'}
            try:
                return session.post(
                    self.service.encode('utf-8'),
                    data=xml.encode('utf-8'),
                    headers=headers
                )
            except Exception as error:
                messages.add_message(
                    request,
                    messages.WARNING,
                    _(u'Error during service logout %(service)s:\n%(error)s') %
                    {'service': self.service, 'error':error}
                )

class ServiceTicket(Ticket):
    """A Service Ticket"""
    value = models.CharField(max_length=255, default=_gen_st, unique=True)
    def __unicode__(self):
        return u"ServiceTicket(%s, %s, %s)" % (self.user, self.value, self.service)
class ProxyTicket(Ticket):
    """A Proxy Ticket"""
    value = models.CharField(max_length=255, default=_gen_pt, unique=True)
    def __unicode__(self):
        return u"ProxyTicket(%s, %s, %s)" % (self.user, self.value, self.service)
class ProxyGrantingTicket(Ticket):
    """A Proxy Granting Ticket"""
    value = models.CharField(max_length=255, default=_gen_pgt, unique=True)
    def __unicode__(self):
        return u"ProxyGrantingTicket(%s, %s, %s)" % (self.user, self.value, self.service)

class Proxy(models.Model):
    """A list of proxies on `ProxyTicket`"""
    class Meta:
        ordering = ("-pk", )
    url = models.CharField(max_length=255)
    proxy_ticket = models.ForeignKey(ProxyTicket, related_name="proxies")

    def __unicode__(self):
        return self.url

