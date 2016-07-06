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
"""views for the app"""
from .default_settings import settings

from django.shortcuts import render, redirect
from django.core.urlresolvers import reverse
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext as _
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.middleware.csrf import CsrfViewMiddleware
from django.views.generic import View
from django.utils.encoding import python_2_unicode_compatible

import re
import logging
import pprint
import requests
from lxml import etree
from datetime import timedelta
from importlib import import_module

import cas_server.utils as utils
import cas_server.forms as forms
import cas_server.models as models

from .utils import json_response
from .models import ServiceTicket, ProxyTicket, ProxyGrantingTicket
from .models import ServicePattern, FederatedIendityProvider, FederatedUser
from .federate import CASFederateValidateUser

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore

logger = logging.getLogger(__name__)


class AttributesMixin(object):
    """mixin for the attributs methode"""

    # pylint: disable=too-few-public-methods

    def attributes(self):
        """regerate attributes list for template rendering"""
        attributes = []
        for key, value in self.ticket.attributs.items():
            if isinstance(value, list):
                for elt in value:
                    attributes.append((key, elt))
            else:
                attributes.append((key, value))
        return attributes


class LogoutMixin(object):
    """destroy CAS session utils"""
    def logout(self, all_session=False):
        """effectively destroy CAS session"""
        session_nb = 0
        username = self.request.session.get("username")
        if username:
            if all_session:
                logger.info("Logging out user %s from all of they sessions." % username)
            else:
                logger.info("Logging out user %s." % username)
        # logout the user from the current session
        try:
            user = models.User.objects.get(
                username=username,
                session_key=self.request.session.session_key
            )
            if settings.CAS_FEDERATE:
                models.FederateSLO.objects.filter(
                    username=username,
                    session_key=self.request.session.session_key
                ).delete()
            self.request.session.flush()
            user.logout(self.request)
            user.delete()
            session_nb += 1
        except models.User.DoesNotExist:
            # if user not found in database, flush the session anyway
            self.request.session.flush()

        # If all_session is set logout user from alternative sessions
        if all_session:
            for user in models.User.objects.filter(username=username):
                session = SessionStore(session_key=user.session_key)
                session.flush()
                user.logout(self.request)
                user.delete()
                session_nb += 1
        logger.info("User %s logged out" % username)
        return session_nb


class LogoutView(View, LogoutMixin):
    """destroy CAS session (logout) view"""

    request = None
    service = None

    def init_get(self, request):
        """Initialize GET received parameters"""
        self.request = request
        self.service = request.GET.get('service')
        self.url = request.GET.get('url')
        self.ajax = settings.CAS_ENABLE_AJAX_AUTH and 'HTTP_X_AJAX' in request.META

    def get(self, request, *args, **kwargs):
        """methode called on GET request on this view"""
        logger.info("logout requested")
        self.init_get(request)
        # if CAS federation mode is enable, bakup the provider before flushing the sessions
        if settings.CAS_FEDERATE:
            try:
                user = FederatedUser.get_from_federated_username(
                    self.request.session.get("username")
                )
                auth = CASFederateValidateUser(user.provider, service_url="")
            except FederatedUser.DoesNotExist:
                auth = None
        session_nb = self.logout(self.request.GET.get("all"))
        # if CAS federation mode is enable, redirect to user CAS logout page
        if settings.CAS_FEDERATE:
            if auth is not None:
                params = utils.copy_params(request.GET)
                url = auth.get_logout_url()
                return HttpResponseRedirect(utils.update_url(url, params))
        # if service is set, redirect to service after logout
        if self.service:
            list(messages.get_messages(request))  # clean messages before leaving the django app
            return HttpResponseRedirect(self.service)
        elif self.url:
            list(messages.get_messages(request))  # clean messages before leaving the django app
            return HttpResponseRedirect(self.url)
        # else redirect to login page
        else:
            if session_nb == 1:
                logout_msg = _(
                    "<h3>Logout successful</h3>"
                    "You have successfully logged out from the Central Authentication Service. "
                    "For security reasons, exit your web browser."
                )
            elif session_nb > 1:
                logout_msg = _(
                    "<h3>Logout successful</h3>"
                    "You have successfully logged out from %s sessions of the Central "
                    "Authentication Service. "
                    "For security reasons, exit your web browser."
                ) % session_nb
            else:
                logout_msg = _(
                    "<h3>Logout successful</h3>"
                    "You were already logged out from the Central Authentication Service. "
                    "For security reasons, exit your web browser."
                )

            if settings.CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT:
                messages.add_message(request, messages.SUCCESS, logout_msg)
                if self.ajax:
                    url = reverse("cas_server:login")
                    data = {
                        'status': 'success',
                        'detail': 'logout',
                        'url': url,
                        'session_nb': session_nb
                    }
                    return json_response(request, data)
                else:
                    return redirect("cas_server:login")
            else:
                if self.ajax:
                    data = {'status': 'success', 'detail': 'logout', 'session_nb': session_nb}
                    return json_response(request, data)
                else:
                    return render(
                        request,
                        settings.CAS_LOGOUT_TEMPLATE,
                        utils.context({'logout_msg': logout_msg})
                    )


class FederateAuth(View):
    """view to authenticated user agains a backend CAS then CAS_FEDERATE is True"""
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        """dispatch different http request to the methods of the same name"""
        return super(FederateAuth, self).dispatch(request, *args, **kwargs)

    @staticmethod
    def get_cas_client(request, provider):
        """return a CAS client object matching provider"""
        service_url = utils.get_current_url(request, {"ticket", "provider"})
        return CASFederateValidateUser(provider, service_url)

    def post(self, request, provider=None):
        """method called on POST request"""
        if not settings.CAS_FEDERATE:
            logger.warning("CAS_FEDERATE is False, set it to True to use the federated mode")
            return redirect("cas_server:login")
        # POST with a provider, this is probably an SLO request
        try:
            provider = FederatedIendityProvider.objects.get(suffix=provider)
            auth = self.get_cas_client(request, provider)
            try:
                auth.clean_sessions(request.POST['logoutRequest'])
            except (KeyError, AttributeError):
                pass
            return HttpResponse("ok")
        # else, a User is trying to log in using an identity provider
        except FederatedIendityProvider.DoesNotExist:
            # Manually checking for csrf to protect the code below
            reason = CsrfViewMiddleware().process_view(request, None, (), {})
            if reason is not None:  # pragma: no cover (csrf checks are disabled during tests)
                return reason  # Failed the test, stop here.
            form = forms.FederateSelect(request.POST)
            if form.is_valid():
                params = utils.copy_params(
                    request.POST,
                    ignore={"provider", "csrfmiddlewaretoken", "ticket"}
                )
                url = utils.reverse_params(
                    "cas_server:federateAuth",
                    kwargs=dict(provider=form.cleaned_data["provider"].suffix),
                    params=params
                )
                response = HttpResponseRedirect(url)
                if form.cleaned_data["remember"]:
                    max_age = settings.CAS_FEDERATE_REMEMBER_TIMEOUT
                    utils.set_cookie(
                        response,
                        "_remember_provider",
                        form.cleaned_data["provider"].suffix,
                        max_age
                    )
                return response
            else:
                return redirect("cas_server:login")

    def get(self, request, provider=None):
        """method called on GET request"""
        if not settings.CAS_FEDERATE:
            logger.warning("CAS_FEDERATE is False, set it to True to use the federated mode")
            return redirect("cas_server:login")
        if self.request.session.get("authenticated"):
            logger.warning("User already authenticated, dropping federate authentication request")
            return redirect("cas_server:login")
        try:
            provider = FederatedIendityProvider.objects.get(suffix=provider)
            auth = self.get_cas_client(request, provider)
            if 'ticket' not in request.GET:
                logger.info("Trying to authenticate again %s" % auth.provider.server_url)
                return HttpResponseRedirect(auth.get_login_url())
            else:
                ticket = request.GET['ticket']
                if auth.verify_ticket(ticket):
                    logger.info(
                        "Got a valid ticket for %s from %s" % (
                            auth.username,
                            auth.provider.server_url
                        )
                    )
                    params = utils.copy_params(request.GET, ignore={"ticket"})
                    request.session["federate_username"] = auth.federated_username
                    request.session["federate_ticket"] = ticket
                    auth.register_slo(auth.federated_username, request.session.session_key, ticket)
                    url = utils.reverse_params("cas_server:login", params)
                    return HttpResponseRedirect(url)
                else:
                    logger.info(
                        "Got a invalid ticket for %s from %s. Retrying to authenticate" % (
                            auth.username,
                            auth.provider.server_url
                        )
                    )
                    return HttpResponseRedirect(auth.get_login_url())
        except FederatedIendityProvider.DoesNotExist:
            logger.warning("Identity provider suffix %s not found" % provider)
            return redirect("cas_server:login")


class LoginView(View, LogoutMixin):
    """credential requestor / acceptor"""

    # pylint: disable=too-many-instance-attributes
    # Nine is reasonable in this case.

    user = None
    form = None

    request = None
    service = None
    renew = None
    gateway = None
    method = None
    ajax = None

    renewed = False
    warned = False

    # used if CAS_FEDERATE is True
    username = None
    ticket = None

    INVALID_LOGIN_TICKET = 1
    USER_LOGIN_OK = 2
    USER_LOGIN_FAILURE = 3
    USER_ALREADY_LOGGED = 4
    USER_AUTHENTICATED = 5
    USER_NOT_AUTHENTICATED = 6

    def init_post(self, request):
        """Initialize POST received parameters"""
        self.request = request
        self.service = request.POST.get('service')
        self.renew = bool(request.POST.get('renew') and request.POST['renew'] != "False")
        self.gateway = request.POST.get('gateway')
        self.method = request.POST.get('method')
        self.ajax = settings.CAS_ENABLE_AJAX_AUTH and 'HTTP_X_AJAX' in request.META
        if request.POST.get('warned') and request.POST['warned'] != "False":
            self.warned = True
        self.warn = request.POST.get('warn')
        if settings.CAS_FEDERATE:
            self.username = request.POST.get('username')
            self.ticket = request.POST.get('ticket')

    def gen_lt(self):
        """Generate a new LoginTicket and add it to the list of valid LT for the user"""
        self.request.session['lt'] = self.request.session.get('lt', []) + [utils.gen_lt()]
        if len(self.request.session['lt']) > 100:
            self.request.session['lt'] = self.request.session['lt'][-100:]

    def check_lt(self):
        """Check is the POSTed LoginTicket is valid, if yes invalide it"""
        # save LT for later check
        lt_valid = self.request.session.get('lt', [])
        lt_send = self.request.POST.get('lt')
        # generate a new LT (by posting the LT has been consumed)
        self.gen_lt()
        # check if send LT is valid
        if lt_valid is None or lt_send not in lt_valid:
            return False
        else:
            self.request.session['lt'].remove(lt_send)
            self.request.session['lt'] = self.request.session['lt']
            return True

    def post(self, request, *args, **kwargs):
        """methode called on POST request on this view"""
        self.init_post(request)
        ret = self.process_post()
        if ret == self.INVALID_LOGIN_TICKET:
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u"Invalid login ticket")
            )
        elif ret == self.USER_LOGIN_OK:
            self.user = models.User.objects.get_or_create(
                username=self.request.session['username'],
                session_key=self.request.session.session_key
            )[0]
            self.user.save()
        elif ret == self.USER_LOGIN_FAILURE:  # bad user login
            if settings.CAS_FEDERATE:
                self.ticket = None
                self.username = None
                self.init_form()
            self.logout()
        elif ret == self.USER_ALREADY_LOGGED:
            pass
        else:
            raise EnvironmentError("invalid output for LoginView.process_post")  # pragma: no cover
        return self.common()

    def process_post(self):
        """
            Analyse the POST request:
                * check that the LoginTicket is valid
                * check that the user sumited credentials are valid
        """
        if not self.check_lt():
            values = self.request.POST.copy()
            # if not set a new LT and fail
            values['lt'] = self.request.session['lt'][-1]
            self.init_form(values)
            logger.warning("Receive an invalid login ticket")
            return self.INVALID_LOGIN_TICKET
        elif not self.request.session.get("authenticated") or self.renew:
            self.init_form(self.request.POST)
            if self.form.is_valid():
                self.request.session.set_expiry(0)
                self.request.session["username"] = self.form.cleaned_data['username']
                self.request.session["warn"] = True if self.form.cleaned_data.get("warn") else False
                self.request.session["authenticated"] = True
                self.renewed = True
                self.warned = True
                logger.info("User %s successfully authenticated" % self.request.session["username"])
                return self.USER_LOGIN_OK
            else:
                logger.warning("A logging attemps failed")
                return self.USER_LOGIN_FAILURE
        else:
            logger.warning("Receuve a logging attempt whereas the user is already logged")
            return self.USER_ALREADY_LOGGED

    def init_get(self, request):
        """Initialize GET received parameters"""
        self.request = request
        self.service = request.GET.get('service')
        self.renew = bool(request.GET.get('renew') and request.GET['renew'] != "False")
        self.gateway = request.GET.get('gateway')
        self.method = request.GET.get('method')
        self.ajax = settings.CAS_ENABLE_AJAX_AUTH and 'HTTP_X_AJAX' in request.META
        self.warn = request.GET.get('warn')
        if settings.CAS_FEDERATE:
            self.username = request.session.get("federate_username")
            self.ticket = request.session.get("federate_ticket")
            if self.username:
                del request.session["federate_username"]
            if self.ticket:
                del request.session["federate_ticket"]

    def get(self, request, *args, **kwargs):
        """methode called on GET request on this view"""
        self.init_get(request)
        self.process_get()
        return self.common()

    def process_get(self):
        """Analyse the GET request"""
        # generate a new LT
        self.gen_lt()
        if not self.request.session.get("authenticated") or self.renew:
            self.init_form()
            return self.USER_NOT_AUTHENTICATED
        return self.USER_AUTHENTICATED

    def init_form(self, values=None):
        """Initialization of the good form depending of POST and GET parameters"""
        form_initial = {
            'service': self.service,
            'method': self.method,
            'warn': self.warn or self.request.session.get("warn"),
            'lt': self.request.session['lt'][-1],
            'renew': self.renew
        }
        if settings.CAS_FEDERATE:
            if self.username and self.ticket:
                form_initial['username'] = self.username
                form_initial['password'] = self.ticket
                form_initial['ticket'] = self.ticket
                self.form = forms.FederateUserCredential(
                    values,
                    initial=form_initial
                )
            else:
                self.form = forms.FederateSelect(values, initial=form_initial)
        else:
            self.form = forms.UserCredential(
                values,
                initial=form_initial
            )

    def service_login(self):
        """Perform login agains a service"""
        try:
            # is the service allowed
            service_pattern = ServicePattern.validate(self.service)
            # is the current user allowed on this service
            service_pattern.check_user(self.user)
            # if the user has asked to be warned before any login to a service
            if self.request.session.get("warn", True) and not self.warned:
                messages.add_message(
                    self.request,
                    messages.WARNING,
                    _(u"Authentication has been required by service %(name)s (%(url)s)") %
                    {'name': service_pattern.name, 'url': self.service}
                )
                if self.ajax:
                    data = {"status": "error", "detail": "confirmation needed"}
                    return json_response(self.request, data)
                else:
                    warn_form = forms.WarnForm(initial={
                        'service': self.service,
                        'renew': self.renew,
                        'gateway': self.gateway,
                        'method': self.method,
                        'warned': True,
                        'lt': self.request.session['lt'][-1]
                    })
                    return render(
                        self.request,
                        settings.CAS_WARN_TEMPLATE,
                        utils.context({'form': warn_form})
                    )
            else:
                # redirect, using method ?
                list(messages.get_messages(self.request))  # clean messages before leaving django
                redirect_url = self.user.get_service_url(
                    self.service,
                    service_pattern,
                    renew=self.renewed
                )
                if not self.ajax:
                    return HttpResponseRedirect(redirect_url)
                else:
                    data = {"status": "success", "detail": "auth", "url": redirect_url}
                    return json_response(self.request, data)
        except ServicePattern.DoesNotExist:
            error = 1
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u'Service %(url)s non allowed.') % {'url': self.service}
            )
        except models.BadUsername:
            error = 2
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u"Username non allowed")
            )
        except models.BadFilter:
            error = 3
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u"User charateristics non allowed")
            )
        except models.UserFieldNotDefined:
            error = 4
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u"The attribut %(field)s is needed to use"
                  u" that service") % {'field': service_pattern.user_field}
            )

        # if gateway is set and auth failed redirect to the service without authentication
        if self.gateway and not self.ajax:
            list(messages.get_messages(self.request))  # clean messages before leaving django
            return HttpResponseRedirect(self.service)

        if not self.ajax:
            return render(
                self.request,
                settings.CAS_LOGGED_TEMPLATE,
                utils.context({'session': self.request.session})
            )
        else:
            data = {"status": "error", "detail": "auth", "code": error}
            return json_response(self.request, data)

    def authenticated(self):
        """Processing authenticated users"""
        try:
            self.user = models.User.objects.get(
                username=self.request.session.get("username"),
                session_key=self.request.session.session_key
            )
        except models.User.DoesNotExist:
            logger.warning(
                "User %s seems authenticated but is not found in the database." % (
                    self.request.session.get("username"),
                )
            )
            self.logout()
            if self.ajax:
                data = {
                    "status": "error",
                    "detail": "login required",
                    "url": utils.reverse_params("cas_server:login", params=self.request.GET)
                }
                return json_response(self.request, data)
            else:
                return utils.redirect_params("cas_server:login", params=self.request.GET)

        # if login agains a service is self.requestest
        if self.service:
            return self.service_login()
        else:
            if self.ajax:
                data = {"status": "success", "detail": "logged"}
                return json_response(self.request, data)
            else:
                return render(
                    self.request,
                    settings.CAS_LOGGED_TEMPLATE,
                    utils.context({'session': self.request.session})
                )

    def not_authenticated(self):
        """Processing non authenticated users"""
        if self.service:
            try:
                service_pattern = ServicePattern.validate(self.service)
                if self.gateway and not self.ajax:
                    # clean messages before leaving django
                    list(messages.get_messages(self.request))
                    return HttpResponseRedirect(self.service)
                if self.request.session.get("authenticated") and self.renew:
                    messages.add_message(
                        self.request,
                        messages.WARNING,
                        _(u"Authentication renewal required by service %(name)s (%(url)s).") %
                        {'name': service_pattern.name, 'url': self.service}
                    )
                else:
                    messages.add_message(
                        self.request,
                        messages.WARNING,
                        _(u"Authentication required by service %(name)s (%(url)s).") %
                        {'name': service_pattern.name, 'url': self.service}
                    )
            except ServicePattern.DoesNotExist:
                messages.add_message(
                    self.request,
                    messages.ERROR,
                    _(u'Service %s non allowed') % self.service
                )
        if self.ajax:
            data = {
                "status": "error",
                "detail": "login required",
                "url": utils.reverse_params("cas_server:login",  params=self.request.GET)
            }
            return json_response(self.request, data)
        else:
            if settings.CAS_FEDERATE:
                if self.username and self.ticket:
                    return render(
                        self.request,
                        settings.CAS_LOGIN_TEMPLATE,
                        utils.context({
                            'form': self.form,
                            'auto_submit': True,
                            'post_url': reverse("cas_server:login")
                        })
                    )
                else:
                    if (
                        self.request.COOKIES.get('_remember_provider') and
                        FederatedIendityProvider.objects.filter(
                            suffix=self.request.COOKIES['_remember_provider']
                        )
                    ):
                        params = utils.copy_params(self.request.GET)
                        url = utils.reverse_params(
                            "cas_server:federateAuth",
                            params=params,
                            kwargs=dict(provider=self.request.COOKIES['_remember_provider'])
                        )
                        return HttpResponseRedirect(url)
                    else:
                        return render(
                            self.request,
                            settings.CAS_LOGIN_TEMPLATE,
                            utils.context({
                                'form': self.form,
                                'post_url': reverse("cas_server:federateAuth")
                            })
                        )
            else:
                return render(
                    self.request,
                    settings.CAS_LOGIN_TEMPLATE,
                    utils.context({'form': self.form})
                )

    def common(self):
        """Part execute uppon GET and POST request"""
        # if authenticated and successfully renewed authentication if needed
        if self.request.session.get("authenticated") and (not self.renew or self.renewed):
            return self.authenticated()
        else:
            return self.not_authenticated()


class Auth(View):
    """A simple view to validate username/password/service tuple"""
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        """dispatch requests based on method GET, POST, ..."""
        return super(Auth, self).dispatch(request, *args, **kwargs)

    @staticmethod
    def post(request):
        """methode called on GET request on this view"""
        username = request.POST.get('username')
        password = request.POST.get('password')
        service = request.POST.get('service')
        secret = request.POST.get('secret')

        if not settings.CAS_AUTH_SHARED_SECRET:
            return HttpResponse(
                "no\nplease set CAS_AUTH_SHARED_SECRET",
                content_type="text/plain; charset=utf-8"
            )
        if secret != settings.CAS_AUTH_SHARED_SECRET:
            return HttpResponse(u"no\n", content_type="text/plain; charset=utf-8")
        if not username or not password or not service:
            return HttpResponse(u"no\n", content_type="text/plain; charset=utf-8")
        form = forms.UserCredential(
            request.POST,
            initial={
                'service': service,
                'method': 'POST',
                'warn': False
            }
        )
        if form.is_valid():
            try:
                user = models.User.objects.get_or_create(
                    username=form.cleaned_data['username'],
                    session_key=request.session.session_key
                )[0]
                user.save()
                # is the service allowed
                service_pattern = ServicePattern.validate(service)
                # is the current user allowed on this service
                service_pattern.check_user(user)
                if not request.session.get("authenticated"):
                    user.delete()
                return HttpResponse(u"yes\n", content_type="text/plain; charset=utf-8")
            except (ServicePattern.DoesNotExist, models.ServicePatternException):
                return HttpResponse(u"no\n", content_type="text/plain; charset=utf-8")
        else:
            return HttpResponse(u"no\n", content_type="text/plain; charset=utf-8")


class Validate(View):
    """service ticket validation"""
    @staticmethod
    def get(request):
        """methode called on GET request on this view"""
        service = request.GET.get('service')
        ticket = request.GET.get('ticket')
        renew = True if request.GET.get('renew') else False
        if service and ticket:
            try:
                ticket_queryset = ServiceTicket.objects.filter(
                    value=ticket,
                    service=service,
                    validate=False,
                    creation__gt=(timezone.now() - timedelta(seconds=ServiceTicket.VALIDITY))
                )
                if renew:
                    ticket = ticket_queryset.get(renew=True)
                else:
                    ticket = ticket_queryset.get()
                ticket.validate = True
                ticket.save()
                logger.info(
                    "Validate: Service ticket %s validated, user %s authenticated on service %s" % (
                        ticket.value,
                        ticket.user.username,
                        ticket.service
                    )
                )
                if (ticket.service_pattern.user_field and
                        ticket.user.attributs.get(ticket.service_pattern.user_field)):
                    username = ticket.user.attributs.get(
                        ticket.service_pattern.user_field
                    )
                    if isinstance(username, list):
                        # the list is not empty because we wont generate a ticket with a user_field
                        # that evaluate to False
                        username = username[0]
                else:
                    username = ticket.user.username
                return HttpResponse(
                    u"yes\n%s\n" % username,
                    content_type="text/plain; charset=utf-8"
                )
            except ServiceTicket.DoesNotExist:
                logger.warning(
                    (
                        "Validate: Service ticket %s not found or "
                        "already validated, auth to %s failed"
                    ) % (
                        ticket,
                        service
                    )
                )
                return HttpResponse(u"no\n", content_type="text/plain; charset=utf-8")
        else:
            logger.warning("Validate: service or ticket missing")
            return HttpResponse(u"no\n", content_type="text/plain; charset=utf-8")


@python_2_unicode_compatible
class ValidateError(Exception):
    """handle service validation error"""
    def __init__(self, code, msg=""):
        self.code = code
        self.msg = msg
        super(ValidateError, self).__init__(code)

    def __str__(self):
        return u"%s" % self.msg

    def render(self, request):
        """render the error template for the exception"""
        return render(
            request,
            "cas_server/serviceValidateError.xml",
            {'code': self.code, 'msg': self.msg},
            content_type="text/xml; charset=utf-8"
        )


class ValidateService(View, AttributesMixin):
    """service ticket validation [CAS 2.0] and [CAS 3.0]"""
    request = None
    service = None
    ticket = None
    pgt_url = None
    renew = None
    allow_proxy_ticket = False

    def get(self, request):
        """methode called on GET request on this view"""
        self.request = request
        self.service = request.GET.get('service')
        self.ticket = request.GET.get('ticket')
        self.pgt_url = request.GET.get('pgtUrl')
        self.renew = True if request.GET.get('renew') else False

        if not self.service or not self.ticket:
            logger.warning("ValidateService: missing ticket or service")
            return ValidateError(
                u'INVALID_REQUEST',
                u"you must specify a service and a ticket"
            ).render(request)
        else:
            try:
                self.ticket, proxies = self.process_ticket()
                params = {
                    'username': self.ticket.user.username,
                    'attributes': self.attributes(),
                    'proxies': proxies
                }
                if (self.ticket.service_pattern.user_field and
                        self.ticket.user.attributs.get(self.ticket.service_pattern.user_field)):
                    params['username'] = self.ticket.user.attributs.get(
                        self.ticket.service_pattern.user_field
                    )
                    if isinstance(params['username'], list):
                        # the list is not empty because we wont generate a ticket with a user_field
                        # that evaluate to False
                        params['username'] = params['username'][0]
                if self.pgt_url and (
                    self.pgt_url.startswith("https://") or
                    re.match("^http://(127\.0\.0\.1|localhost)(:[0-9]+)?(/.*)?$", self.pgt_url)
                ):
                    return self.process_pgturl(params)
                else:
                    logger.info(
                        "ValidateService: ticket %s validated for user %s on service %s." % (
                            self.ticket.value,
                            self.ticket.user.username,
                            self.ticket.service
                        )
                    )
                    logger.debug(
                        "ValidateService: User attributs are:\n%s" % (
                            pprint.pformat(self.ticket.attributs),
                        )
                    )
                    return render(
                        request,
                        "cas_server/serviceValidate.xml",
                        params,
                        content_type="text/xml; charset=utf-8"
                    )
            except ValidateError as error:
                logger.warning(
                    "ValidateService: validation error: %s %s" % (error.code, error.msg)
                )
                return error.render(request)

    def process_ticket(self):
        """fetch the ticket angains the database and check its validity"""
        try:
            proxies = []
            ticket_class = models.Ticket.get_class(self.ticket)
            if ticket_class:
                ticket_queryset = ticket_class.objects.filter(
                    value=self.ticket,
                    validate=False,
                    creation__gt=(timezone.now() - timedelta(seconds=ServiceTicket.VALIDITY))
                )
                if self.renew:
                    ticket = ticket_queryset.get(renew=True)
                else:
                    ticket = ticket_queryset.get()
                if ticket_class == models.ProxyTicket:
                    for prox in ticket.proxies.all():
                        proxies.append(prox.url)
            else:
                raise ValidateError(u'INVALID_TICKET', self.ticket)
            ticket.validate = True
            ticket.save()
            if ticket.service != self.service:
                raise ValidateError(u'INVALID_SERVICE', self.service)
            return ticket, proxies
        except (ServiceTicket.DoesNotExist, ProxyTicket.DoesNotExist):
            raise ValidateError(u'INVALID_TICKET', 'ticket not found')

    def process_pgturl(self, params):
        """Handle PGT request"""
        try:
            pattern = ServicePattern.validate(self.pgt_url)
            if pattern.proxy_callback:
                proxyid = utils.gen_pgtiou()
                pticket = ProxyGrantingTicket.objects.create(
                    user=self.ticket.user,
                    service=self.pgt_url,
                    service_pattern=pattern,
                    single_log_out=pattern.single_log_out
                )
                url = utils.update_url(self.pgt_url, {'pgtIou': proxyid, 'pgtId': pticket.value})
                try:
                    ret = requests.get(url, verify=settings.CAS_PROXY_CA_CERTIFICATE_PATH)
                    if ret.status_code == 200:
                        params['proxyGrantingTicket'] = proxyid
                    else:
                        pticket.delete()
                    logger.info(
                        (
                            "ValidateService: ticket %s validated for user %s on service %s. "
                            "Proxy Granting Ticket transmited to %s."
                        ) % (
                            self.ticket.value,
                            self.ticket.user.username,
                            self.ticket.service,
                            self.pgt_url
                        )
                    )
                    logger.debug(
                        "ValidateService: User attributs are:\n%s" % (
                            pprint.pformat(self.ticket.attributs),
                        )
                    )
                    return render(
                        self.request,
                        "cas_server/serviceValidate.xml",
                        params,
                        content_type="text/xml; charset=utf-8"
                    )
                except requests.exceptions.RequestException as error:
                    error = utils.unpack_nested_exception(error)
                    raise ValidateError(
                        u'INVALID_PROXY_CALLBACK',
                        u"%s: %s" % (type(error), str(error))
                    )
            else:
                raise ValidateError(
                    u'INVALID_PROXY_CALLBACK',
                    u"callback url not allowed by configuration"
                )
        except ServicePattern.DoesNotExist:
            raise ValidateError(
                u'INVALID_PROXY_CALLBACK',
                u'callback url not allowed by configuration'
            )


class Proxy(View):
    """proxy ticket service"""

    request = None
    pgt = None
    target_service = None

    def get(self, request):
        """methode called on GET request on this view"""
        self.request = request
        self.pgt = request.GET.get('pgt')
        self.target_service = request.GET.get('targetService')
        try:
            if self.pgt and self.target_service:
                return self.process_proxy()
            else:
                raise ValidateError(
                    u'INVALID_REQUEST',
                    u"you must specify and pgt and targetService"
                )
        except ValidateError as error:
            logger.warning("Proxy: validation error: %s %s" % (error.code, error.msg))
            return error.render(request)

    def process_proxy(self):
        """handle PT request"""
        try:
            # is the target service allowed
            pattern = ServicePattern.validate(self.target_service)
            if not pattern.proxy:
                raise ValidateError(
                    u'UNAUTHORIZED_SERVICE',
                    u'the service %s do not allow proxy ticket' % self.target_service
                )
            # is the proxy granting ticket valid
            ticket = ProxyGrantingTicket.objects.get(
                value=self.pgt,
                creation__gt=(timezone.now() - timedelta(seconds=ProxyGrantingTicket.VALIDITY)),
                validate=False
            )
            # is the pgt user allowed on the target service
            pattern.check_user(ticket.user)
            pticket = ticket.user.get_ticket(
                ProxyTicket,
                self.target_service,
                pattern,
                renew=False)
            models.Proxy.objects.create(proxy_ticket=pticket, url=ticket.service)
            logger.info(
                "Proxy ticket created for user %s on service %s." % (
                    ticket.user.username,
                    self.target_service
                )
            )
            return render(
                self.request,
                "cas_server/proxy.xml",
                {'ticket': pticket.value},
                content_type="text/xml; charset=utf-8"
            )
        except ProxyGrantingTicket.DoesNotExist:
            raise ValidateError(u'INVALID_TICKET', u'PGT %s not found' % self.pgt)
        except ServicePattern.DoesNotExist:
            raise ValidateError(u'UNAUTHORIZED_SERVICE', self.target_service)
        except (models.BadUsername, models.BadFilter, models.UserFieldNotDefined):
            raise ValidateError(
                u'UNAUTHORIZED_USER',
                u'User %s not allowed on %s' % (ticket.user.username, self.target_service)
            )


@python_2_unicode_compatible
class SamlValidateError(Exception):
    """handle saml validation error"""
    def __init__(self, code, msg=""):
        self.code = code
        self.msg = msg
        super(SamlValidateError, self).__init__(code)

    def __str__(self):
        return u"%s" % self.msg

    def render(self, request):
        """render the error template for the exception"""
        return render(
            request,
            "cas_server/samlValidateError.xml",
            {
                'code': self.code,
                'msg': self.msg,
                'IssueInstant': timezone.now().isoformat(),
                'ResponseID': utils.gen_saml_id()
            },
            content_type="text/xml; charset=utf-8"
        )


class SamlValidate(View, AttributesMixin):
    """SAML ticket validation"""
    request = None
    target = None
    ticket = None
    root = None

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        """dispatch requests based on method GET, POST, ..."""
        return super(SamlValidate, self).dispatch(request, *args, **kwargs)

    def post(self, request):
        """methode called on POST request on this view"""
        self.request = request
        self.target = request.GET.get('TARGET')
        self.root = etree.fromstring(request.body)
        try:
            self.ticket = self.process_ticket()
            expire_instant = (self.ticket.creation +
                              timedelta(seconds=self.ticket.VALIDITY)).isoformat()
            attributes = self.attributes()
            params = {
                'IssueInstant': timezone.now().isoformat(),
                'expireInstant': expire_instant,
                'Recipient': self.target,
                'ResponseID': utils.gen_saml_id(),
                'username': self.ticket.user.username,
                'attributes': attributes
            }
            if (self.ticket.service_pattern.user_field and
                    self.ticket.user.attributs.get(self.ticket.service_pattern.user_field)):
                params['username'] = self.ticket.user.attributs.get(
                    self.ticket.service_pattern.user_field
                )
                if isinstance(params['username'], list):
                    # the list is not empty because we wont generate a ticket with a user_field
                    # that evaluate to False
                    params['username'] = params['username'][0]
            logger.info(
                "SamlValidate: ticket %s validated for user %s on service %s." % (
                    self.ticket.value,
                    self.ticket.user.username,
                    self.ticket.service
                )
            )
            logger.debug(
                "SamlValidate: User attributs are:\n%s" % pprint.pformat(self.ticket.attributs)
            )

            return render(
                request,
                "cas_server/samlValidate.xml",
                params,
                content_type="text/xml; charset=utf-8"
            )
        except SamlValidateError as error:
            logger.warning("SamlValidate: validation error: %s %s" % (error.code, error.msg))
            return error.render(request)

    def process_ticket(self):
        """validate ticket from SAML XML body"""
        try:
            auth_req = self.root.getchildren()[1].getchildren()[0]
            ticket = auth_req.getchildren()[0].text
            ticket_class = models.Ticket.get_class(ticket)
            if ticket_class:
                ticket = ticket_class.objects.get(
                    value=ticket,
                    validate=False,
                    creation__gt=(timezone.now() - timedelta(seconds=ServiceTicket.VALIDITY))
                )
            else:
                raise SamlValidateError(
                    u'AuthnFailed',
                    u'ticket %s should begin with PT- or ST-' % ticket
                )
            ticket.validate = True
            ticket.save()
            if ticket.service != self.target:
                raise SamlValidateError(
                    u'AuthnFailed',
                    u'TARGET %s do not match ticket service' % self.target
                )
            return ticket
        except (IndexError, KeyError):
            raise SamlValidateError(u'VersionMismatch')
        except (ServiceTicket.DoesNotExist, ProxyTicket.DoesNotExist):
            raise SamlValidateError(u'AuthnFailed', u'ticket %s not found' % ticket)
