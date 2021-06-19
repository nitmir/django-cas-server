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
from .default_settings import settings, SessionStore

from django.db import models
from django.db.models import Q
from django.contrib import messages
from django.utils import timezone
try:
    from django.utils.encoding import python_2_unicode_compatible
    from django.utils.translation import ugettext_lazy as _
except ImportError:
    def python_2_unicode_compatible(func):
        """
        We use Django >= 3.0 with Python >= 3.4, we don't need Python 2 compatibility.
        """
        return func
    from django.utils.translation import gettext_lazy as _
from django.core.mail import send_mail

import re
import sys
import smtplib
import logging
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from requests_futures.sessions import FuturesSession

from cas_server import utils
from . import VERSION

#: logger facility
logger = logging.getLogger(__name__)


class JsonAttributes(models.Model):
    """
        Bases: :class:`django.db.models.Model`

        A base class for models storing attributes as a json
    """

    class Meta:
        abstract = True

    #: The attributes json encoded
    _attributs = models.TextField(default=None, null=True, blank=True)

    @property
    def attributs(self):
        """The attributes"""
        if self._attributs is not None:
            return utils.json.loads(self._attributs)

    @attributs.setter
    def attributs(self, value):
        """attributs property setter"""
        self._attributs = utils.json_encode(value)


@python_2_unicode_compatible
class FederatedIendityProvider(models.Model):
    """
        Bases: :class:`django.db.models.Model`

        An identity provider for the federated mode
    """
    class Meta:
        verbose_name = _(u"identity provider")
        verbose_name_plural = _(u"identity providers")
    #: Suffix append to backend CAS returned username: ``returned_username`` @ ``suffix``.
    #: it must be unique.
    suffix = models.CharField(
        max_length=30,
        unique=True,
        verbose_name=_(u"suffix"),
        help_text=_(
            u"Suffix append to backend CAS returned "
            u"username: ``returned_username`` @ ``suffix``."
        )
    )
    #: URL to the root of the CAS server application. If login page is
    #: https://cas.example.net/cas/login then :attr:`server_url` should be
    #: https://cas.example.net/cas/
    server_url = models.CharField(max_length=255, verbose_name=_(u"server url"))
    #: Version of the CAS protocol to use when sending requests the the backend CAS.
    cas_protocol_version = models.CharField(
        max_length=30,
        choices=[
            ("1", "CAS 1.0"),
            ("2", "CAS 2.0"),
            ("3", "CAS 3.0"),
            ("CAS_2_SAML_1_0", "SAML 1.1")
        ],
        verbose_name=_(u"CAS protocol version"),
        help_text=_(
            u"Version of the CAS protocol to use when sending requests the the backend CAS."
        ),
        default="3"
    )
    #: Name for this identity provider displayed on the login page.
    verbose_name = models.CharField(
        max_length=255,
        verbose_name=_(u"verbose name"),
        help_text=_(u"Name for this identity provider displayed on the login page.")
    )
    #: Position of the identity provider on the login page. Identity provider are sorted using the
    #: (:attr:`pos`, :attr:`verbose_name`, :attr:`suffix`) attributes.
    pos = models.IntegerField(
        default=100,
        verbose_name=_(u"position"),
        help_text=_(
            (
                u"Position of the identity provider on the login page. "
                u"Identity provider are sorted using the "
                u"(position, verbose name, suffix) attributes."
            )
        )
    )
    #: Display the provider on the login page. Beware that this do not disable the identity
    #: provider, it just hide it on the login page. User will always be able to log in using this
    #: provider by fetching ``/federate/suffix``.
    display = models.BooleanField(
        default=True,
        verbose_name=_(u"display"),
        help_text=_("Display the provider on the login page.")
    )

    def __str__(self):
        return self.verbose_name

    @staticmethod
    def build_username_from_suffix(username, suffix):
        """
            Transform backend username into federated username using ``suffix``

            :param unicode username: A CAS backend returned username
            :param unicode suffix: A suffix identifying the CAS backend
            :return: The federated username: ``username`` @ ``suffix``.
            :rtype: unicode
        """
        return u'%s@%s' % (username, suffix)

    def build_username(self, username):
        """
            Transform backend username into federated username

            :param unicode username: A CAS backend returned username
            :return: The federated username: ``username`` @ :attr:`suffix`.
            :rtype: unicode
        """
        return u'%s@%s' % (username, self.suffix)


@python_2_unicode_compatible
class FederatedUser(JsonAttributes):
    """
        Bases: :class:`JsonAttributes`

        A federated user as returner by a CAS provider (username and attributes)
    """
    class Meta:
        unique_together = ("username", "provider")
        verbose_name = _("Federated user")
        verbose_name_plural = _("Federated users")
    #: The user username returned by the CAS backend on successful ticket validation
    username = models.CharField(max_length=124)
    #: A foreign key to :class:`FederatedIendityProvider`
    provider = models.ForeignKey(FederatedIendityProvider, on_delete=models.CASCADE)
    #: The last ticket used to authenticate :attr:`username` against :attr:`provider`
    ticket = models.CharField(max_length=255)
    #: Last update timespampt. Usually, the last time :attr:`ticket` has been set.
    last_update = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.federated_username

    @property
    def federated_username(self):
        """The federated username with a suffix for the current :class:`FederatedUser`."""
        return self.provider.build_username(self.username)

    @classmethod
    def get_from_federated_username(cls, username):
        """
            :return: A :class:`FederatedUser` object from a federated ``username``
            :rtype: :class:`FederatedUser`
        """
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
        """remove old unused :class:`FederatedUser`"""
        federated_users = cls.objects.filter(
            last_update__lt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_TIMEOUT))
        )
        known_users = {user.username for user in User.objects.all()}
        for user in federated_users:
            if user.federated_username not in known_users:
                user.delete()


class FederateSLO(models.Model):
    """
        Bases: :class:`django.db.models.Model`

        An association between a CAS provider ticket and a (username, session) for processing SLO
    """
    class Meta:
        unique_together = ("username", "session_key", "ticket")
    #: the federated username with the ``@`` component
    username = models.CharField(max_length=30)
    #: the session key for the session :attr:`username` has been authenticated using :attr:`ticket`
    session_key = models.CharField(max_length=40, blank=True, null=True)
    #: The ticket used to authenticate :attr:`username`
    ticket = models.CharField(max_length=255, db_index=True)

    @classmethod
    def clean_deleted_sessions(cls):
        """remove old :class:`FederateSLO` object for which the session do not exists anymore"""
        for federate_slo in cls.objects.all():
            if not SessionStore(session_key=federate_slo.session_key).get('authenticated'):
                federate_slo.delete()


@python_2_unicode_compatible
class UserAttributes(JsonAttributes):
    """
        Bases: :class:`JsonAttributes`

        Local cache of the user attributes, used then needed
    """
    class Meta:
        verbose_name = _("User attributes cache")
        verbose_name_plural = _("User attributes caches")
    #: The username of the user for which we cache attributes
    username = models.CharField(max_length=155, unique=True)

    def __str__(self):
        return self.username

    @classmethod
    def clean_old_entries(cls):
        """Remove :class:`UserAttributes` for which no more :class:`User` exists."""
        for user in cls.objects.all():
            if User.objects.filter(username=user.username).count() == 0:
                user.delete()


@python_2_unicode_compatible
class User(models.Model):
    """
        Bases: :class:`django.db.models.Model`

        A user logged into the CAS
    """
    class Meta:
        unique_together = ("username", "session_key")
        verbose_name = _("User")
        verbose_name_plural = _("Users")
    #: The session key of the current authenticated user
    session_key = models.CharField(max_length=40, blank=True, null=True)
    #: The username of the current authenticated user
    username = models.CharField(max_length=250)
    #: Last time the authenticated user has do something (auth, fetch ticket, etc…)
    date = models.DateTimeField(auto_now=True)
    #: last time the user logged
    last_login = models.DateTimeField(auto_now_add=True)

    def delete(self, *args, **kwargs):
        """
            Remove the current :class:`User`. If ``settings.CAS_FEDERATE`` is ``True``, also delete
            the corresponding :class:`FederateSLO` object.
        """
        if settings.CAS_FEDERATE:
            FederateSLO.objects.filter(
                username=self.username,
                session_key=self.session_key
            ).delete()
        super(User, self).delete(*args, **kwargs)

    @classmethod
    def clean_old_entries(cls):
        """
            Remove :class:`User` objects inactive since more that
            :django:setting:`SESSION_COOKIE_AGE` and send corresponding SingleLogOut requests.
        """
        filter = Q(date__lt=(timezone.now() - timedelta(seconds=settings.SESSION_COOKIE_AGE)))
        if settings.CAS_TGT_VALIDITY is not None:
            filter |= Q(
                last_login__lt=(timezone.now() - timedelta(seconds=settings.CAS_TGT_VALIDITY))
            )
        users = cls.objects.filter(filter)
        for user in users:
            user.logout()
        users.delete()

    @classmethod
    def clean_deleted_sessions(cls):
        """Remove :class:`User` objects where the corresponding session do not exists anymore."""
        for user in cls.objects.all():
            if not SessionStore(session_key=user.session_key).get('authenticated'):
                user.logout()
                user.delete()

    @property
    def attributs(self):
        """
            Property.
            A fresh :class:`dict` for the user attributes, using ``settings.CAS_AUTH_CLASS`` if
            possible, and if not, try to fallback to cached attributes (actually only used for ldap
            auth class with bind password check mthode).
        """
        try:
            return utils.import_attr(settings.CAS_AUTH_CLASS)(self.username).attributs()
        except NotImplementedError:
            try:
                user = UserAttributes.objects.get(username=self.username)
                attributes = user.attributs
                if attributes is not None:
                    return attributes
                else:
                    return {}
            except UserAttributes.DoesNotExist:
                return {}

    def __str__(self):
        return u"%s - %s" % (self.username, self.session_key)

    def logout(self, request=None):
        """
            Send SLO requests to all services the user is logged in.

            :param request: The current django HttpRequest to display possible failure to the user.
            :type request: :class:`django.http.HttpRequest` or :obj:`NoneType<types.NoneType>`
        """
        ticket_classes = [ProxyGrantingTicket, ServiceTicket, ProxyTicket]
        for error in Ticket.send_slos(
            [ticket_class.objects.filter(user=self) for ticket_class in ticket_classes]
        ):
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
            Generate a ticket using ``ticket_class`` for the service
            ``service`` matching ``service_pattern`` and asking or not for
            authentication renewal with ``renew``

            :param type ticket_class: :class:`ServiceTicket` or :class:`ProxyTicket` or
               :class:`ProxyGrantingTicket`.
            :param unicode service: The service url for which we want a ticket.
            :param ServicePattern service_pattern: The service pattern matching ``service``.
               Beware that ``service`` must match :attr:`ServicePattern.pattern` and the current
               :class:`User` must pass :meth:`ServicePattern.check_user`. These checks are not done
               here and you must perform them before calling this method.
            :param bool renew: Should be ``True`` if authentication has been renewed. Must be
                ``False`` otherwise.
            :return: A :class:`Ticket` object.
            :rtype: :class:`ServiceTicket` or :class:`ProxyTicket` or
               :class:`ProxyGrantingTicket`.
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
        """
            Return the url to which the user must be redirected to
            after a Service Ticket has been generated

            :param unicode service: The service url for which we want a ticket.
            :param ServicePattern service_pattern: The service pattern matching ``service``.
               Beware that ``service`` must match :attr:`ServicePattern.pattern` and the current
               :class:`User` must pass :meth:`ServicePattern.check_user`. These checks are not done
               here and you must perform them before calling this method.
            :param bool renew: Should be ``True`` if authentication has been renewed. Must be
                ``False`` otherwise.
            :return unicode: The service url with the ticket GET param added.
            :rtype: unicode
        """
        ticket = self.get_ticket(ServiceTicket, service, service_pattern, renew)
        url = utils.update_url(service, {'ticket': ticket.value})
        logger.info("Service ticket created for service %s by user %s." % (service, self.username))
        return url


class ServicePatternException(Exception):
    """
        Bases: :class:`exceptions.Exception`

        Base exception of exceptions raised in the ServicePattern model"""
    pass


class BadUsername(ServicePatternException):
    """
        Bases: :class:`ServicePatternException`

        Exception raised then an non allowed username try to get a ticket for a service
    """
    pass


class BadFilter(ServicePatternException):
    """
        Bases: :class:`ServicePatternException`

        Exception raised then a user try to get a ticket for a service and do not reach a condition
    """
    pass


class UserFieldNotDefined(ServicePatternException):
    """
        Bases: :class:`ServicePatternException`

        Exception raised then a user try to get a ticket for a service using as username
        an attribut not present on this user
    """
    pass


@python_2_unicode_compatible
class ServicePattern(models.Model):
    """
        Bases: :class:`django.db.models.Model`

        Allowed services pattern against services are tested to
    """
    class Meta:
        ordering = ("pos", )
        verbose_name = _("Service pattern")
        verbose_name_plural = _("Services patterns")

    #: service patterns are sorted using the :attr:`pos` attribute
    pos = models.IntegerField(
        default=100,
        verbose_name=_(u"position"),
        help_text=_(u"service patterns are sorted using the position attribute")
    )
    #: A name for the service (this can bedisplayed to the user on the login page)
    name = models.CharField(
        max_length=255,
        unique=True,
        blank=True,
        null=True,
        verbose_name=_(u"name"),
        help_text=_(u"A name for the service")
    )
    #: A regular expression matching services. "Will usually looks like
    #: '^https://some\\.server\\.com/path/.*$'. As it is a regular expression, special character
    #: must be escaped with a '\\'.
    pattern = models.CharField(
        max_length=255,
        unique=True,
        verbose_name=_(u"pattern"),
        help_text=_(
            "A regular expression matching services. "
            "Will usually looks like '^https://some\\.server\\.com/path/.*$'."
            "As it is a regular expression, special character must be escaped with a '\\'."
        ),
        validators=[utils.regexpr_validator]
    )
    #: Name of the attribute to transmit as username, if empty the user login is used
    user_field = models.CharField(
        max_length=255,
        default="",
        blank=True,
        verbose_name=_(u"user field"),
        help_text=_("Name of the attribute to transmit as username, empty = login")
    )
    #: A boolean allowing to limit username allowed to connect to :attr:`usernames`.
    restrict_users = models.BooleanField(
        default=False,
        verbose_name=_(u"restrict username"),
        help_text=_("Limit username allowed to connect to the list provided bellow")
    )
    #: A boolean allowing to deliver :class:`ProxyTicket` to the service.
    proxy = models.BooleanField(
        default=False,
        verbose_name=_(u"proxy"),
        help_text=_("Proxy tickets can be delivered to the service")
    )
    #: A boolean allowing the service to be used as a proxy callback (via the pgtUrl GET param)
    #: to deliver :class:`ProxyGrantingTicket`.
    proxy_callback = models.BooleanField(
        default=False,
        verbose_name=_(u"proxy callback"),
        help_text=_("can be used as a proxy callback to deliver PGT")
    )
    #: Enable SingleLogOut for the service. Old validaed tickets for the service will be kept
    #: until ``settings.CAS_TICKET_TIMEOUT`` after what a SLO request is send to the service and
    #: the ticket is purged from database. A SLO can be send earlier if the user log-out.
    single_log_out = models.BooleanField(
        default=False,
        verbose_name=_(u"single log out"),
        help_text=_("Enable SLO for the service")
    )
    #: An URL where the SLO request will be POST. If empty the service url will be used.
    #: This is usefull for non HTTP proxied services like smtp or imap.
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
        """
            Check if ``user`` if allowed to use theses services. If ``user`` is not allowed,
            raises one of :class:`BadFilter`, :class:`UserFieldNotDefined`, :class:`BadUsername`

            :param User user: a :class:`User` object
            :raises BadUsername: if :attr:`restrict_users` if ``True`` and :attr:`User.username`
                is not within :attr:`usernames`.
            :raises BadFilter: if a :class:`FilterAttributValue` condition of :attr:`filters`
                connot be verified.
            :raises UserFieldNotDefined: if :attr:`user_field` is defined and its value is not
                within :attr:`User.attributs`.
            :return: ``True``
            :rtype: bool
        """
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
                bad_filter = (filtre.pattern, filtre.attribut, user.attributs.get(filtre.attribut))
                logger.warning(
                    "User constraint failed for %s, service %s: %s do not match %s %s." % (
                        (user.username, self.name) + bad_filter
                    )
                )
                raise BadFilter('%s do not match %s %s' % bad_filter)
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
        """
            Get a :class:`ServicePattern` intance from a service url.

            :param unicode service: A service url
            :return: A :class:`ServicePattern` instance matching ``service``.
            :rtype: :class:`ServicePattern`
            :raises ServicePattern.DoesNotExist: if no :class:`ServicePattern` is matching
                ``service``.
        """
        for service_pattern in cls.objects.all().order_by('pos'):
            if re.match(service_pattern.pattern, service):
                return service_pattern
        logger.warning("Service %s not allowed." % service)
        raise cls.DoesNotExist()


@python_2_unicode_compatible
class Username(models.Model):
    """
        Bases: :class:`django.db.models.Model`

        A list of allowed usernames on a :class:`ServicePattern`
    """
    #: username allowed to connect to the service
    value = models.CharField(
        max_length=255,
        verbose_name=_(u"username"),
        help_text=_(u"username allowed to connect to the service")
    )
    #: ForeignKey to a :class:`ServicePattern`. :class:`Username` instances for a
    #: :class:`ServicePattern` are accessible thought its :attr:`ServicePattern.usernames`
    #: attribute.
    service_pattern = models.ForeignKey(
        ServicePattern,
        related_name="usernames",
        on_delete=models.CASCADE
    )

    def __str__(self):
        return self.value


@python_2_unicode_compatible
class ReplaceAttributName(models.Model):
    """
        Bases: :class:`django.db.models.Model`

        A replacement of an attribute name for a :class:`ServicePattern`. It also tell to transmit
        an attribute of :attr:`User.attributs` to the service. An empty :attr:`replace` mean
        to use the original attribute name.
    """
    class Meta:
        unique_together = ('name', 'replace', 'service_pattern')
    #: Name the attribute: a key of :attr:`User.attributs`
    name = models.CharField(
        max_length=255,
        verbose_name=_(u"name"),
        help_text=_(u"name of an attribute to send to the service, use * for all attributes")
    )
    #: The name of the attribute to transmit to the service. If empty, the value of :attr:`name`
    #: is used.
    replace = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_(u"replace"),
        help_text=_(u"name under which the attribute will be show "
                    u"to the service. empty = default name of the attribut")
    )
    #: ForeignKey to a :class:`ServicePattern`. :class:`ReplaceAttributName` instances for a
    #: :class:`ServicePattern` are accessible thought its :attr:`ServicePattern.attributs`
    #: attribute.
    service_pattern = models.ForeignKey(
        ServicePattern,
        related_name="attributs",
        on_delete=models.CASCADE
    )

    def __str__(self):
        if not self.replace:
            return self.name
        else:
            return u"%s → %s" % (self.name, self.replace)


@python_2_unicode_compatible
class FilterAttributValue(models.Model):
    """
        Bases: :class:`django.db.models.Model`

        A filter on :attr:`User.attributs` for a :class:`ServicePattern`. If a :class:`User` do not
        have an attribute :attr:`attribut` or its value do not match :attr:`pattern`, then
        :meth:`ServicePattern.check_user` will raises :class:`BadFilter` if called with that user.
    """
    #: The name of a user attribute
    attribut = models.CharField(
        max_length=255,
        verbose_name=_(u"attribute"),
        help_text=_(u"Name of the attribute which must verify pattern")
    )
    #: A regular expression the attribute :attr:`attribut` value must verify. If :attr:`attribut`
    #: if a list, only one of the list values needs to match.
    pattern = models.CharField(
        max_length=255,
        verbose_name=_(u"pattern"),
        help_text=_(u"a regular expression"),
        validators=[utils.regexpr_validator]
    )
    #: ForeignKey to a :class:`ServicePattern`. :class:`FilterAttributValue` instances for a
    #: :class:`ServicePattern` are accessible thought its :attr:`ServicePattern.filters`
    #: attribute.
    service_pattern = models.ForeignKey(
        ServicePattern,
        related_name="filters",
        on_delete=models.CASCADE
    )

    def __str__(self):
        return u"%s %s" % (self.attribut, self.pattern)


@python_2_unicode_compatible
class ReplaceAttributValue(models.Model):
    """
        Bases: :class:`django.db.models.Model`

        A replacement (using a regular expression) of an attribute value for a
        :class:`ServicePattern`.
    """
    #: Name the attribute: a key of :attr:`User.attributs`
    attribut = models.CharField(
        max_length=255,
        verbose_name=_(u"attribute"),
        help_text=_(u"Name of the attribute for which the value must be replace")
    )
    #: A regular expression matching the part of the attribute value that need to be changed
    pattern = models.CharField(
        max_length=255,
        verbose_name=_(u"pattern"),
        help_text=_(u"An regular expression maching whats need to be replaced"),
        validators=[utils.regexpr_validator]
    )
    #: The replacement to what is mached by :attr:`pattern`. groups are capture by \\1, \\2 …
    replace = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_(u"replace"),
        help_text=_(u"replace expression, groups are capture by \\1, \\2 …")
    )
    #: ForeignKey to a :class:`ServicePattern`. :class:`ReplaceAttributValue` instances for a
    #: :class:`ServicePattern` are accessible thought its :attr:`ServicePattern.replacements`
    #: attribute.
    service_pattern = models.ForeignKey(
        ServicePattern,
        related_name="replacements",
        on_delete=models.CASCADE
    )

    def __str__(self):
        return u"%s %s %s" % (self.attribut, self.pattern, self.replace)


@python_2_unicode_compatible
class Ticket(JsonAttributes):
    """
        Bases: :class:`JsonAttributes`

        Generic class for a Ticket
    """
    class Meta:
        abstract = True
    #: ForeignKey to a :class:`User`.
    user = models.ForeignKey(User, related_name="%(class)s", on_delete=models.CASCADE)
    #: A boolean. ``True`` if the ticket has been validated
    validate = models.BooleanField(default=False)
    #: The service url for the ticket
    service = models.TextField()
    #: ForeignKey to a :class:`ServicePattern`. The :class:`ServicePattern` corresponding to
    #: :attr:`service`. Use :meth:`ServicePattern.validate` to find it.
    service_pattern = models.ForeignKey(
        ServicePattern,
        related_name="%(class)s",
        on_delete=models.CASCADE
    )
    #: Date of the ticket creation
    creation = models.DateTimeField(auto_now_add=True)
    #: A boolean. ``True`` if the user has just renew his authentication
    renew = models.BooleanField(default=False)
    #: A boolean. Set to :attr:`service_pattern` attribute
    #: :attr:`ServicePattern.single_log_out` value.
    single_log_out = models.BooleanField(default=False)

    #: Max duration between ticket creation and its validation. Any validation attempt for the
    #: ticket after :attr:`creation` + VALIDITY will fail as if the ticket do not exists.
    VALIDITY = settings.CAS_TICKET_VALIDITY
    #: Time we keep ticket with :attr:`single_log_out` set to ``True`` before sending SingleLogOut
    #: requests.
    TIMEOUT = settings.CAS_TICKET_TIMEOUT

    class DoesNotExist(Exception):
        """raised in :meth:`Ticket.get` then ticket prefix and ticket classes mismatch"""
        pass

    def __str__(self):
        return u"Ticket-%s" % self.pk

    @staticmethod
    def send_slos(queryset_list):
        """
            Send SLO requests to each ticket of each queryset of ``queryset_list``

            :param list queryset_list: A list a :class:`Ticket` queryset
            :return: A list of possibly encoutered :class:`Exception`
            :rtype: list
        """
        # sending SLO to timed-out validated tickets
        async_list = []
        session = FuturesSession(
            executor=ThreadPoolExecutor(max_workers=settings.CAS_SLO_MAX_PARALLEL_REQUESTS)
        )
        errors = []
        for queryset in queryset_list:
            for ticket in queryset:
                ticket.logout(session, async_list)
            queryset.delete()
        for future in async_list:
            if future:  # pragma: no branch (should always be true)
                try:
                    future.result()
                except Exception as error:
                    errors.append(error)
        return errors

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
        queryset = cls.objects.filter(
            creation__lt=(timezone.now() - timedelta(seconds=cls.TIMEOUT))
        )
        for error in cls.send_slos([queryset]):
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
            xml = utils.logout_request(self.value)
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
    def get_class(ticket, classes=None):
        """
            Return the ticket class of ``ticket``

            :param unicode ticket: A ticket
            :param list classes: Optinal arguement. A list of possible :class:`Ticket` subclasses
            :return: The class corresponding to ``ticket`` (:class:`ServiceTicket` or
                :class:`ProxyTicket` or :class:`ProxyGrantingTicket`) if found among ``classes,
                ``None`` otherwise.
            :rtype: :obj:`type` or :obj:`NoneType<types.NoneType>`
        """
        if classes is None:  # pragma: no cover (not used)
            classes = [ServiceTicket, ProxyTicket, ProxyGrantingTicket]
        for ticket_class in classes:
            if ticket.startswith(ticket_class.PREFIX):
                return ticket_class

    def username(self):
        """
            The username to send on ticket validation

            :return: The value of the corresponding user attribute if
                :attr:`service_pattern`.user_field is set, the user username otherwise.
        """
        if self.service_pattern.user_field and self.user.attributs.get(
            self.service_pattern.user_field
        ):
            username = self.user.attributs[self.service_pattern.user_field]
            if isinstance(username, list):
                # the list is not empty because we wont generate a ticket with a user_field
                # that evaluate to False
                username = username[0]
        else:
            username = self.user.username
        return username

    def attributs_flat(self):
        """
            generate attributes list for template rendering

            :return: An list of (attribute name, attribute value) of all user attributes flatened
                (no nested list)
            :rtype: :obj:`list` of :obj:`tuple` of :obj:`unicode`
        """
        attributes = []
        for key, value in self.attributs.items():
            if isinstance(value, list):
                for elt in value:
                    attributes.append((key, elt))
            else:
                attributes.append((key, value))
        return attributes

    @classmethod
    def get(cls, ticket, renew=False, service=None):
        """
            Search the database for a valid ticket with provided arguments

           :param unicode ticket: A ticket value
           :param bool renew: Is authentication renewal needed
           :param unicode service: Optional argument. The ticket service
           :raises Ticket.DoesNotExist: if no class is found for the ticket prefix
           :raises cls.DoesNotExist: if ``ticket`` value is not found in th database
           :return: a :class:`Ticket` instance
           :rtype: Ticket
        """
        # If the method class is the ticket abstract class, search for the submited ticket
        # class using its prefix. Assuming ticket is a ProxyTicket or a ServiceTicket
        if cls == Ticket:
            ticket_class = cls.get_class(ticket, classes=[ServiceTicket, ProxyTicket])
        # else use the method class
        else:
            ticket_class = cls
        # If ticket prefix is wrong, raise DoesNotExist
        if cls != Ticket and not ticket.startswith(cls.PREFIX):
            raise Ticket.DoesNotExist()
        if ticket_class:
            # search for the ticket that is not yet validated and is still valid
            ticket_queryset = ticket_class.objects.filter(
                value=ticket,
                validate=False,
                creation__gt=(timezone.now() - timedelta(seconds=ticket_class.VALIDITY))
            )
            # if service is specified, add it the the queryset
            if service is not None:
                ticket_queryset = ticket_queryset.filter(service=service)
            # only require renew if renew is True, otherwise it do not matter if renew is True
            # or False.
            if renew:
                ticket_queryset = ticket_queryset.filter(renew=True)
            # fetch the ticket ``MultipleObjectsReturned`` is never raised as the ticket value
            # is unique across the database
            ticket = ticket_queryset.get()
            # For ServiceTicket and Proxyticket, mark it as validated before returning
            if ticket_class != ProxyGrantingTicket:
                ticket.validate = True
                ticket.save()
            return ticket
        # If no class found for the ticket, raise DoesNotExist
        else:
            raise Ticket.DoesNotExist()


@python_2_unicode_compatible
class ServiceTicket(Ticket):
    """
        Bases: :class:`Ticket`

        A Service Ticket
    """
    #: The ticket prefix used to differentiate it from other tickets types
    PREFIX = settings.CAS_SERVICE_TICKET_PREFIX
    #: The ticket value
    value = models.CharField(max_length=255, default=utils.gen_st, unique=True)

    def __str__(self):
        return u"ServiceTicket-%s" % self.pk


@python_2_unicode_compatible
class ProxyTicket(Ticket):
    """
        Bases: :class:`Ticket`

        A Proxy Ticket
    """
    #: The ticket prefix used to differentiate it from other tickets types
    PREFIX = settings.CAS_PROXY_TICKET_PREFIX
    #: The ticket value
    value = models.CharField(max_length=255, default=utils.gen_pt, unique=True)

    def __str__(self):
        return u"ProxyTicket-%s" % self.pk


@python_2_unicode_compatible
class ProxyGrantingTicket(Ticket):
    """
        Bases: :class:`Ticket`

        A Proxy Granting Ticket
    """
    #: The ticket prefix used to differentiate it from other tickets types
    PREFIX = settings.CAS_PROXY_GRANTING_TICKET_PREFIX
    #: ProxyGranting ticket are never validated. However, they can be used during :attr:`VALIDITY`
    #: to get :class:`ProxyTicket` for :attr:`user`
    VALIDITY = settings.CAS_PGT_VALIDITY
    #: The ticket value
    value = models.CharField(max_length=255, default=utils.gen_pgt, unique=True)

    def __str__(self):
        return u"ProxyGrantingTicket-%s" % self.pk


@python_2_unicode_compatible
class Proxy(models.Model):
    """
        Bases: :class:`django.db.models.Model`

        A list of proxies on :class:`ProxyTicket`
    """
    class Meta:
        ordering = ("-pk", )
    #: Service url of the PGT used for getting the associated :class:`ProxyTicket`
    url = models.CharField(max_length=255)
    #: ForeignKey to a :class:`ProxyTicket`. :class:`Proxy` instances for a
    #: :class:`ProxyTicket` are accessible thought its :attr:`ProxyTicket.proxies`
    #: attribute.
    proxy_ticket = models.ForeignKey(ProxyTicket, related_name="proxies", on_delete=models.CASCADE)

    def __str__(self):
        return self.url


class NewVersionWarning(models.Model):
    """
        Bases: :class:`django.db.models.Model`

        The last new version available version sent
    """
    version = models.CharField(max_length=255)

    @classmethod
    def send_mails(cls):
        """
            For each new django-cas-server version, if the current instance is not up to date
            send one mail to ``settings.ADMINS``.
        """
        if settings.CAS_NEW_VERSION_EMAIL_WARNING and settings.ADMINS:
            try:
                obj = cls.objects.get()
            except cls.DoesNotExist:
                obj = NewVersionWarning.objects.create(version=VERSION)
            LAST_VERSION = utils.last_version()
            if LAST_VERSION is not None and LAST_VERSION != obj.version:
                if utils.decode_version(VERSION) < utils.decode_version(LAST_VERSION):
                    try:
                        send_mail(
                            (
                                '%sA new version of django-cas-server is available'
                            ) % settings.EMAIL_SUBJECT_PREFIX,
                            u'''
A new version of the django-cas-server is available.

Your version: %s
New version: %s

Upgrade using:
    * pip install -U django-cas-server
    * fetching the last release on
      https://github.com/nitmir/django-cas-server/ or on
      https://pypi.org/project/django-cas-server/

After upgrade, do not forget to run:
    * ./manage.py migrate
    * ./manage.py collectstatic
and to reload your wsgi server (apache2, uwsgi, gunicord, etc…)

--\u0020
django-cas-server
'''.strip() % (VERSION, LAST_VERSION),
                            settings.SERVER_EMAIL,
                            ["%s <%s>" % admin for admin in settings.ADMINS],
                            fail_silently=False,
                        )
                        obj.version = LAST_VERSION
                        obj.save()
                    except smtplib.SMTPException as error:  # pragma: no cover (should not happen)
                        logger.error("Unable to send new version mail: %s" % error)
