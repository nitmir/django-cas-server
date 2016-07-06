# -*- coding: utf-8 -*-
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License version 3 for
# more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (c) 2015-2016 Valentin Samir
"""models for the app"""
from .default_settings import settings

from django.db import models
from django.db.models import Q
from django.contrib import messages
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.utils.encoding import python_2_unicode_compatible
from picklefield.fields import PickledObjectField

import re
import sys
import logging
from importlib import import_module
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from requests_futures.sessions import FuturesSession

import cas_server.utils as utils

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore

logger = logging.getLogger(__name__)


@python_2_unicode_compatible
class FederatedIendityProvider(models.Model):
    """An identity provider for the federated mode"""
    class Meta:
        verbose_name = _("identity provider")
        verbose_name_plural = _("identity providers")
    suffix = models.CharField(
        max_length=30,
        unique=True,
        verbose_name=_(u"suffix"),
        help_text=_("Suffix append to backend CAS returner username: `returned_username`@`suffix`")
    )
    server_url = models.CharField(max_length=255, verbose_name=_(u"server url"))
    cas_protocol_version = models.CharField(
        max_length=30,
        choices=[
            ("1", "CAS 1.0"),
            ("2", "CAS 2.0"),
            ("3", "CAS 3.0"),
            ("CAS_2_SAML_1_0", "SAML 1.1")
        ],
        verbose_name=_(u"CAS protocol version"),
        help_text=_("Version of the CAS protocol to use when sending requests the the backend CAS"),
        default="3"
    )
    verbose_name = models.CharField(
        max_length=255,
        verbose_name=_(u"verbose name"),
        help_text=_("Name for this identity provider displayed on the login page")
    )
    pos = models.IntegerField(
        default=100,
        verbose_name=_(u"position"),
        help_text=_(
            (
                u"Identity provider are sorted using the "
                u"(position, verbose name, suffix) attributes"
            )
        )
    )
    display = models.BooleanField(
        default=True,
        verbose_name=_(u"display"),
        help_text=_("Display the provider on the login page")
    )

    def __str__(self):
        return self.verbose_name

    @staticmethod
    def build_username_from_suffix(username, suffix):
        """Transform backend username into federated username using `suffix`"""
        return u'%s@%s' % (username, suffix)

    def build_username(self, username):
        """Transform backend username into federated username"""
        return u'%s@%s' % (username, self.suffix)


@python_2_unicode_compatible
class FederatedUser(models.Model):
    """A federated user as returner by a CAS provider (username and attributes)"""
    class Meta:
        unique_together = ("username", "provider")
    username = models.CharField(max_length=124)
    provider = models.ForeignKey(FederatedIendityProvider, on_delete=models.CASCADE)
    attributs = PickledObjectField()
    ticket = models.CharField(max_length=255)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.federated_username

    @property
    def federated_username(self):
        """return the federated username with a suffix"""
        return self.provider.build_username(self.username)

    @classmethod
    def get_from_federated_username(cls, username):
        """return a FederatedUser object from a federated username"""
        if username is None:
            raise cls.DoesNotExist()
        else:
            component = username.split('@')
            username = '@'.join(component[:-1])
            suffix = component[-1]
            try:
                provider = FederatedIendityProvider.objects.get(suffix=suffix)
                return cls.objects.get(username=username, provider=provider)
            except FederatedIendityProvider.DoesNotExist:
                raise cls.DoesNotExist()

    @classmethod
    def clean_old_entries(cls):
        """remove old unused federated users"""
        federated_users = cls.objects.filter(
            last_update__lt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_TIMEOUT))
        )
        known_users = {user.username for user in User.objects.all()}
        for user in federated_users:
            if user.federated_username not in known_users:
                user.delete()


class FederateSLO(models.Model):
    """An association between a CAS provider ticket and a (username, session) for processing SLO"""
    class Meta:
        unique_together = ("username", "session_key", "ticket")
    username = models.CharField(max_length=30)
    session_key = models.CharField(max_length=40, blank=True, null=True)
    ticket = models.CharField(max_length=255, db_index=True)

    @classmethod
    def clean_deleted_sessions(cls):
        """remove old object for which the session do not exists anymore"""
        for federate_slo in cls.objects.all():
            if not SessionStore(session_key=federate_slo.session_key).get('authenticated'):
                federate_slo.delete()


@python_2_unicode_compatible
class User(models.Model):
    """A user logged into the CAS"""
    class Meta:
        unique_together = ("username", "session_key")
        verbose_name = _("User")
        verbose_name_plural = _("Users")
    session_key = models.CharField(max_length=40, blank=True, null=True)
    username = models.CharField(max_length=30)
    date = models.DateTimeField(auto_now=True)

    def delete(self, *args, **kwargs):
        """remove the User"""
        if settings.CAS_FEDERATE:
            FederateSLO.objects.filter(
                username=self.username,
                session_key=self.session_key
            ).delete()
        super(User, self).delete(*args, **kwargs)

    @classmethod
    def clean_old_entries(cls):
        """Remove users inactive since more that SESSION_COOKIE_AGE"""
        users = cls.objects.filter(
            date__lt=(timezone.now() - timedelta(seconds=settings.SESSION_COOKIE_AGE))
        )
        for user in users:
            user.logout()
        users.delete()

    @classmethod
    def clean_deleted_sessions(cls):
        """Remove user where the session do not exists anymore"""
        for user in cls.objects.all():
            if not SessionStore(session_key=user.session_key).get('authenticated'):
                user.logout()
                user.delete()

    @property
    def attributs(self):
        """return a fresh dict for the user attributs"""
        return utils.import_attr(settings.CAS_AUTH_CLASS)(self.username).attributs()

    def __str__(self):
        return u"%s - %s" % (self.username, self.session_key)

    def logout(self, request=None):
        """Sending SLO request to all services the user logged in"""
        async_list = []
        session = FuturesSession(
            executor=ThreadPoolExecutor(max_workers=settings.CAS_SLO_MAX_PARALLEL_REQUESTS)
        )
        # first invalidate all Tickets
        ticket_classes = [ProxyGrantingTicket, ServiceTicket, ProxyTicket]
        for ticket_class in ticket_classes:
            queryset = ticket_class.objects.filter(user=self)
            for ticket in queryset:
                ticket.logout(session, async_list)
            queryset.delete()
        for future in async_list:
            if future:  # pragma: no branch (should always be true)
                try:
                    future.result()
                except Exception as error:
                    logger.warning(
                        "Error during SLO for user %s: %s" % (
                            self.username,
                            error
                        )
                    )
                    if request is not None:
                        error = utils.unpack_nested_exception(error)
                        messages.add_message(
                            request,
                            messages.WARNING,
                            _(u'Error during service logout %s') % error
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
            (a.attribut, (a.pattern, a.replace)) for a in service_pattern.replacements.all()
        )
        service_attributs = {}
        for (key, value) in self.attributs.items():
            if key in attributs or '*' in attributs:
                if key in replacements:
                    if isinstance(value, list):
                        for index, subval in enumerate(value):
                            value[index] = re.sub(
                                replacements[key][0],
                                replacements[key][1],
                                subval
                            )
                    else:
                        value = re.sub(replacements[key][0], replacements[key][1], value)
                service_attributs[attributs.get(key, key)] = value
        ticket = ticket_class.objects.create(
            user=self,
            attributs=service_attributs,
            service=service,
            renew=renew,
            service_pattern=service_pattern,
            single_log_out=service_pattern.single_log_out
        )
        ticket.save()
        self.save()
        return ticket

    def get_service_url(self, service, service_pattern, renew):
        """Return the url to which the user must be redirected to
        after a Service Ticket has been generated"""
        ticket = self.get_ticket(ServiceTicket, service, service_pattern, renew)
        url = utils.update_url(service, {'ticket': ticket.value})
        logger.info("Service ticket created for service %s by user %s." % (service, self.username))
        return url


class ServicePatternException(Exception):
    """Base exception of exceptions raised in the ServicePattern model"""
    pass


class BadUsername(ServicePatternException):
    """Exception raised then an non allowed username
    try to get a ticket for a service"""
    pass


class BadFilter(ServicePatternException):
    """"Exception raised then a user try
    to get a ticket for a service and do not reach a condition"""
    pass


class UserFieldNotDefined(ServicePatternException):
    """Exception raised then a user try to get a ticket for a service
    using as username an attribut not present on this user"""
    pass


@python_2_unicode_compatible
class ServicePattern(models.Model):
    """Allowed services pattern agains services are tested to"""
    class Meta:
        ordering = ("pos", )
        verbose_name = _("Service pattern")
        verbose_name_plural = _("Services patterns")

    pos = models.IntegerField(
        default=100,
        verbose_name=_(u"position"),
        help_text=_(u"service patterns are sorted using the position attribute")
    )
    name = models.CharField(
        max_length=255,
        unique=True,
        blank=True,
        null=True,
        verbose_name=_(u"name"),
        help_text=_(u"A name for the service")
    )
    pattern = models.CharField(
        max_length=255,
        unique=True,
        verbose_name=_(u"pattern"),
        help_text=_(
            "A regular expression matching services. "
            "Will usually looks like '^https://some\\.server\\.com/path/.*$'."
            "As it is a regular expression, special character must be escaped with a '\\'."
        )
    )
    user_field = models.CharField(
        max_length=255,
        default="",
        blank=True,
        verbose_name=_(u"user field"),
        help_text=_("Name of the attribut to transmit as username, empty = login")
    )
    restrict_users = models.BooleanField(
        default=False,
        verbose_name=_(u"restrict username"),
        help_text=_("Limit username allowed to connect to the list provided bellow")
    )
    proxy = models.BooleanField(
        default=False,
        verbose_name=_(u"proxy"),
        help_text=_("Proxy tickets can be delivered to the service")
    )
    proxy_callback = models.BooleanField(
        default=False,
        verbose_name=_(u"proxy callback"),
        help_text=_("can be used as a proxy callback to deliver PGT")
    )
    single_log_out = models.BooleanField(
        default=False,
        verbose_name=_(u"single log out"),
        help_text=_("Enable SLO for the service")
    )

    single_log_out_callback = models.CharField(
        max_length=255,
        default="",
        blank=True,
        verbose_name=_(u"single log out callback"),
        help_text=_(u"URL where the SLO request will be POST. empty = service url\n"
                    u"This is usefull for non HTTP proxied services.")
    )

    def __str__(self):
        return u"%s: %s" % (self.pos, self.pattern)

    def check_user(self, user):
        """Check if `user` if allowed to use theses services"""
        if self.restrict_users and not self.usernames.filter(value=user.username):
            logger.warning("Username %s not allowed on service %s" % (user.username, self.name))
            raise BadUsername()
        for filtre in self.filters.all():
            if isinstance(user.attributs.get(filtre.attribut, []), list):
                attrs = user.attributs.get(filtre.attribut, [])
            else:
                attrs = [user.attributs[filtre.attribut]]
            for value in attrs:
                if re.match(filtre.pattern, str(value)):
                    break
            else:
                logger.warning(
                    "User constraint failed for %s, service %s: %s do not match %s %s." % (
                        user.username,
                        self.name,
                        filtre.pattern,
                        filtre.attribut,
                        user.attributs.get(filtre.attribut)
                    )
                )
                raise BadFilter('%s do not match %s %s' % (
                    filtre.pattern,
                    filtre.attribut,
                    user.attributs.get(filtre.attribut)
                ))
        if self.user_field and not user.attributs.get(self.user_field):
            logger.warning(
                "Cannot use %s a loggin for user %s on service %s because it is absent" % (
                    self.user_field,
                    user.username,
                    self.name
                )
            )
            raise UserFieldNotDefined()
        return True

    @classmethod
    def validate(cls, service):
        """Check if a Service Patern match `service` and
        return it, else raise `ServicePattern.DoesNotExist`"""
        for service_pattern in cls.objects.all().order_by('pos'):
            if re.match(service_pattern.pattern, service):
                return service_pattern
        logger.warning("Service %s not allowed." % service)
        raise cls.DoesNotExist()


@python_2_unicode_compatible
class Username(models.Model):
    """A list of allowed usernames on a service pattern"""
    value = models.CharField(
        max_length=255,
        verbose_name=_(u"username"),
        help_text=_(u"username allowed to connect to the service")
    )
    service_pattern = models.ForeignKey(ServicePattern, related_name="usernames")

    def __str__(self):
        return self.value


@python_2_unicode_compatible
class ReplaceAttributName(models.Model):
    """A list of replacement of attributs name for a service pattern"""
    class Meta:
        unique_together = ('name', 'replace', 'service_pattern')
    name = models.CharField(
        max_length=255,
        verbose_name=_(u"name"),
        help_text=_(u"name of an attribut to send to the service, use * for all attributes")
    )
    replace = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_(u"replace"),
        help_text=_(u"name under which the attribut will be show"
                    u"to the service. empty = default name of the attribut")
    )
    service_pattern = models.ForeignKey(ServicePattern, related_name="attributs")

    def __str__(self):
        if not self.replace:
            return self.name
        else:
            return u"%s → %s" % (self.name, self.replace)


@python_2_unicode_compatible
class FilterAttributValue(models.Model):
    """A list of filter on attributs for a service pattern"""
    attribut = models.CharField(
        max_length=255,
        verbose_name=_(u"attribut"),
        help_text=_(u"Name of the attribut which must verify pattern")
    )
    pattern = models.CharField(
        max_length=255,
        verbose_name=_(u"pattern"),
        help_text=_(u"a regular expression")
    )
    service_pattern = models.ForeignKey(ServicePattern, related_name="filters")

    def __str__(self):
        return u"%s %s" % (self.attribut, self.pattern)


@python_2_unicode_compatible
class ReplaceAttributValue(models.Model):
    """Replacement to apply on attributs values for a service pattern"""
    attribut = models.CharField(
        max_length=255,
        verbose_name=_(u"attribut"),
        help_text=_(u"Name of the attribut for which the value must be replace")
    )
    pattern = models.CharField(
        max_length=255,
        verbose_name=_(u"pattern"),
        help_text=_(u"An regular expression maching whats need to be replaced")
    )
    replace = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_(u"replace"),
        help_text=_(u"replace expression, groups are capture by \\1, \\2 …")
    )
    service_pattern = models.ForeignKey(ServicePattern, related_name="replacements")

    def __str__(self):
        return u"%s %s %s" % (self.attribut, self.pattern, self.replace)


@python_2_unicode_compatible
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
    single_log_out = models.BooleanField(default=False)

    VALIDITY = settings.CAS_TICKET_VALIDITY
    TIMEOUT = settings.CAS_TICKET_TIMEOUT

    def __str__(self):
        return u"Ticket-%s" % self.pk

    @classmethod
    def clean_old_entries(cls):
        """Remove old ticket and send SLO to timed-out services"""
        # removing old validated ticket and non validated expired tickets
        cls.objects.filter(
            (
                Q(single_log_out=False) & Q(validate=True)
            ) | (
                Q(validate=False) &
                Q(creation__lt=(timezone.now() - timedelta(seconds=cls.VALIDITY)))
            )
        ).delete()

        # sending SLO to timed-out validated tickets
        async_list = []
        session = FuturesSession(
            executor=ThreadPoolExecutor(max_workers=settings.CAS_SLO_MAX_PARALLEL_REQUESTS)
        )
        queryset = cls.objects.filter(
            creation__lt=(timezone.now() - timedelta(seconds=cls.TIMEOUT))
        )
        for ticket in queryset:
            ticket.logout(session, async_list)
        queryset.delete()
        for future in async_list:
            if future:  # pragma: no branch (should always be true)
                try:
                    future.result()
                except Exception as error:
                    logger.warning("Error durring SLO %s" % error)
                    sys.stderr.write("%r\n" % error)

    def logout(self, session, async_list=None):
        """Send a SLO request to the ticket service"""
        # On logout invalidate the Ticket
        self.validate = True
        self.save()
        if self.validate and self.single_log_out:  # pragma: no branch (should always be true)
            logger.info(
                "Sending SLO requests to service %s for user %s" % (
                    self.service,
                    self.user.username
                )
            )
            xml = u"""<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
 ID="%(id)s" Version="2.0" IssueInstant="%(datetime)s">
<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:NameID>
<samlp:SessionIndex>%(ticket)s</samlp:SessionIndex>
</samlp:LogoutRequest>""" % \
                {
                    'id': utils.gen_saml_id(),
                    'datetime': timezone.now().isoformat(),
                    'ticket':  self.value
                }
            if self.service_pattern.single_log_out_callback:
                url = self.service_pattern.single_log_out_callback
            else:
                url = self.service
            async_list.append(
                session.post(
                    url.encode('utf-8'),
                    data={'logoutRequest': xml.encode('utf-8')},
                    timeout=settings.CAS_SLO_TIMEOUT
                )
            )

    @staticmethod
    def get_class(ticket):
        for ticket_class in [ServiceTicket, ProxyTicket, ProxyGrantingTicket]:
            if ticket.startswith(ticket_class.PREFIX):
                return ticket_class


@python_2_unicode_compatible
class ServiceTicket(Ticket):
    """A Service Ticket"""
    PREFIX = settings.CAS_SERVICE_TICKET_PREFIX
    value = models.CharField(max_length=255, default=utils.gen_st, unique=True)

    def __str__(self):
        return u"ServiceTicket-%s" % self.pk


@python_2_unicode_compatible
class ProxyTicket(Ticket):
    """A Proxy Ticket"""
    PREFIX = settings.CAS_PROXY_TICKET_PREFIX
    value = models.CharField(max_length=255, default=utils.gen_pt, unique=True)

    def __str__(self):
        return u"ProxyTicket-%s" % self.pk


@python_2_unicode_compatible
class ProxyGrantingTicket(Ticket):
    """A Proxy Granting Ticket"""
    PREFIX = settings.CAS_PROXY_GRANTING_TICKET_PREFIX
    VALIDITY = settings.CAS_PGT_VALIDITY
    value = models.CharField(max_length=255, default=utils.gen_pgt, unique=True)

    def __str__(self):
        return u"ProxyGrantingTicket-%s" % self.pk


@python_2_unicode_compatible
class Proxy(models.Model):
    """A list of proxies on `ProxyTicket`"""
    class Meta:
        ordering = ("-pk", )
    url = models.CharField(max_length=255)
    proxy_ticket = models.ForeignKey(ProxyTicket, related_name="proxies")

    def __str__(self):
        return self.url
