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
from .default_settings import settings, SessionStore

from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.middleware.csrf import CsrfViewMiddleware
from django.views.generic import View
try:
    from django.utils.encoding import python_2_unicode_compatible
    from django.utils.translation import ugettext as _
except ImportError:
    def python_2_unicode_compatible(func):
        """
        We use Django >= 3.0 with Python >= 3.4, we don't need Python 2 compatibility.
        """
        return func
    from django.utils.translation import gettext as _
from django.utils.safestring import mark_safe
try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse

import re
import logging
import pprint
import requests
from lxml import etree
from datetime import timedelta

import cas_server.utils as utils
import cas_server.forms as forms
import cas_server.models as models

from .utils import json_response
from .models import Ticket, ServiceTicket, ProxyTicket, ProxyGrantingTicket
from .models import ServicePattern, FederatedIendityProvider, FederatedUser
from .federate import CASFederateValidateUser

logger = logging.getLogger(__name__)


class LogoutMixin(object):
    """destroy CAS session utils"""

    def logout(self, all_session=False):
        """
            effectively destroy a CAS session

            :param boolean all_session: If ``True`` destroy all the user sessions, otherwise
                destroy the current user session.
            :return: The number of destroyed sessions
            :rtype: int
        """
        # initialize the counter of the number of destroyed sesisons
        session_nb = 0
        # save the current user username before flushing the session
        username = self.request.session.get("username")
        if username:
            if all_session:
                logger.info("Logging out user %s from all sessions." % username)
            else:
                logger.info("Logging out user %s." % username)
        users = []
        # try to get the user from the current session
        try:
            users.append(
                models.User.objects.get(
                    username=username,
                    session_key=self.request.session.session_key
                )
            )
        except models.User.DoesNotExist:
            # if user not found in database, flush the session anyway
            self.request.session.flush()

        # If all_session is set, search all of the user sessions
        if all_session:
            users.extend(
                models.User.objects.filter(
                    username=username
                ).exclude(
                    session_key=self.request.session.session_key
                )
            )

        # Iterate over all user sessions that have to be logged out
        for user in users:
            # get the user session
            session = SessionStore(session_key=user.session_key)
            # flush the session
            session.flush()
            # send SLO requests
            user.logout(self.request)
            # delete the user
            user.delete()
            # increment the destroyed session counter
            session_nb += 1
        if username:
            logger.info("User %s logged out" % username)
        return session_nb


class CsrfExemptView(View):
    """base class for csrf exempt class views"""

    @method_decorator(csrf_exempt)  # csrf is disabled for allowing SLO requests reception
    def dispatch(self, request, *args, **kwargs):
        """
            dispatch different http request to the methods of the same name

            :param django.http.HttpRequest request: The current request object
        """
        return super(CsrfExemptView, self).dispatch(request, *args, **kwargs)


class LogoutView(View, LogoutMixin):
    """destroy CAS session (logout) view"""

    #: current :class:`django.http.HttpRequest` object
    request = None
    #: service GET parameter
    service = None
    #: url GET paramet
    url = None
    #: ``True`` if the HTTP_X_AJAX http header is sent and ``settings.CAS_ENABLE_AJAX_AUTH``
    #: is ``True``, ``False`` otherwise.
    ajax = None

    def init_get(self, request):
        """
            Initialize the :class:`LogoutView` attributes on GET request

            :param django.http.HttpRequest request: The current request object
        """
        self.request = request
        self.service = request.GET.get('service')
        self.url = request.GET.get('url')
        self.ajax = settings.CAS_ENABLE_AJAX_AUTH and 'HTTP_X_AJAX' in request.META

    @staticmethod
    def delete_cookies(response):
        if settings.CAS_REMOVE_DJANGO_SESSION_COOKIE_ON_LOGOUT:
            response.delete_cookie(settings.SESSION_COOKIE_NAME)
        if settings.CAS_REMOVE_DJANGO_CSRF_COOKIE_ON_LOGOUT:
            response.delete_cookie(settings.CSRF_COOKIE_NAME)
        if settings.CAS_REMOVE_DJANGO_LANGUAGE_COOKIE_ON_LOGOUT:
            response.delete_cookie(settings.LANGUAGE_COOKIE_NAME)
        return response

    def get(self, request, *args, **kwargs):
        """
            method called on GET request on this view

            :param django.http.HttpRequest request: The current request object
        """
        logger.info("logout requested")
        # initialize the class attributes
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
        # if CAS federation mode is enable, redirect to user CAS logout page, appending the
        # current querystring
        if settings.CAS_FEDERATE:
            if auth is not None:
                params = utils.copy_params(request.GET, ignore={"forget_provider"})
                url = auth.get_logout_url()
                response = HttpResponseRedirect(utils.update_url(url, params))
                if request.GET.get("forget_provider"):
                    response.delete_cookie("remember_provider")
                return self.delete_cookies(response)
        # if service is set, redirect to service after logout
        if self.service:
            list(messages.get_messages(request))  # clean messages before leaving the django app
            return self.delete_cookies(HttpResponseRedirect(self.service))
        # if service is not set but url is set, redirect to url after logout
        elif self.url:
            list(messages.get_messages(request))  # clean messages before leaving the django app
            return self.delete_cookies(HttpResponseRedirect(self.url))
        else:
            # build logout message depending of the number of sessions the user logs out
            if session_nb == 1:
                logout_msg = mark_safe(_(
                    "<h3>Logout successful</h3>"
                    "You have successfully logged out from the Central Authentication Service. "
                    "For security reasons, close your web browser."
                ))
            elif session_nb > 1:
                logout_msg = mark_safe(_(
                    "<h3>Logout successful</h3>"
                    "You have successfully logged out from %d sessions of the Central "
                    "Authentication Service. "
                    "For security reasons, close your web browser."
                ) % session_nb)
            else:
                logout_msg = mark_safe(_(
                    "<h3>Logout successful</h3>"
                    "You were already logged out from the Central Authentication Service. "
                    "For security reasons, close your web browser."
                ))

            # depending of settings, redirect to the login page with a logout message or display
            # the logout page. The default is to display tge logout page.
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
                    return self.delete_cookies(json_response(request, data))
                else:
                    return self.delete_cookies(redirect("cas_server:login"))
            else:
                if self.ajax:
                    data = {'status': 'success', 'detail': 'logout', 'session_nb': session_nb}
                    return self.delete_cookies(json_response(request, data))
                else:
                    return self.delete_cookies(render(
                        request,
                        settings.CAS_LOGOUT_TEMPLATE,
                        utils.context({'logout_msg': logout_msg})
                    ))


class FederateAuth(CsrfExemptView):
    """
        view to authenticated user against a backend CAS then CAS_FEDERATE is True

        csrf is disabled for allowing SLO requests reception.
    """

    #: current URL used as service URL by the CAS client
    service_url = None

    def get_cas_client(self, request, provider, renew=False):
        """
            return a CAS client object matching provider

            :param django.http.HttpRequest request: The current request object
            :param cas_server.models.FederatedIendityProvider provider: the user identity provider
            :return: The user CAS client object
            :rtype: :class:`federate.CASFederateValidateUser
                <cas_server.federate.CASFederateValidateUser>`
        """
        # compute the current url, ignoring ticket dans provider GET parameters
        service_url = utils.get_current_url(request, {"ticket", "provider"})
        self.service_url = service_url
        return CASFederateValidateUser(provider, service_url, renew=renew)

    def post(self, request, provider=None, *args, **kwargs):
        """
            method called on POST request

            :param django.http.HttpRequest request: The current request object
            :param unicode provider: Optional parameter. The user provider suffix.
        """
        # if settings.CAS_FEDERATE is not True redirect to the login page
        if not settings.CAS_FEDERATE:
            logger.warning("CAS_FEDERATE is False, set it to True to use federation")
            return redirect("cas_server:login")
        # POST with a provider suffix, this is probably an SLO request. csrf is disabled for
        # allowing SLO requests reception
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
            reason = CsrfViewMiddleware(lambda request: HttpResponse()) \
                    .process_view(request, None, (), {})
            if reason is not None:  # pragma: no cover (csrf checks are disabled during tests)
                return reason  # Failed the test, stop here.
            form = forms.FederateSelect(request.POST)
            if form.is_valid():
                params = utils.copy_params(
                    request.POST,
                    ignore={"provider", "csrfmiddlewaretoken", "ticket", "lt"}
                )
                if params.get("renew") == "False":
                    del params["renew"]
                url = utils.reverse_params(
                    "cas_server:federateAuth",
                    kwargs=dict(provider=form.cleaned_data["provider"].suffix),
                    params=params
                )
                return HttpResponseRedirect(url)
            else:
                return redirect("cas_server:login")

    def get(self, request, provider=None):
        """
            method called on GET request

            :param django.http.HttpRequestself. request: The current request object
            :param unicode provider: Optional parameter. The user provider suffix.
        """
        # if settings.CAS_FEDERATE is not True redirect to the login page
        if not settings.CAS_FEDERATE:
            logger.warning("CAS_FEDERATE is False, set it to True to use federation")
            return redirect("cas_server:login")
        renew = bool(request.GET.get('renew') and request.GET['renew'] != "False")
        # Is the user is already authenticated, no need to request authentication to the user
        # identity provider.
        if self.request.session.get("authenticated") and not renew:
            logger.warning("User already authenticated, dropping federated authentication request")
            return redirect("cas_server:login")
        try:
            # get the identity provider from its suffix
            provider = FederatedIendityProvider.objects.get(suffix=provider)
            # get a CAS client for the user identity provider
            auth = self.get_cas_client(request, provider, renew)
            # if no ticket submited, redirect to the identity provider CAS login page
            if 'ticket' not in request.GET:
                logger.info("Trying to authenticate %s again" % auth.provider.server_url)
                return HttpResponseRedirect(auth.get_login_url())
            else:
                ticket = request.GET['ticket']
                try:
                    # if the ticket validation succeed
                    if auth.verify_ticket(ticket):
                        logger.info(
                            "Got a valid ticket for %s from %s" % (
                                auth.username,
                                auth.provider.server_url
                            )
                        )
                        params = utils.copy_params(request.GET, ignore={"ticket", "remember"})
                        request.session["federate_username"] = auth.federated_username
                        request.session["federate_ticket"] = ticket
                        auth.register_slo(
                            auth.federated_username,
                            request.session.session_key,
                            ticket
                        )
                        # redirect to the the login page for the user to become authenticated
                        # thanks to the `federate_username` and `federate_ticket` session parameters
                        url = utils.reverse_params("cas_server:login", params)
                        response = HttpResponseRedirect(url)
                        # If the user has checked "remember my identity provider" store it in a
                        # cookie
                        if request.GET.get("remember"):
                            max_age = settings.CAS_FEDERATE_REMEMBER_TIMEOUT
                            utils.set_cookie(
                                response,
                                "remember_provider",
                                provider.suffix,
                                max_age
                            )
                        return response
                    # else redirect to the identity provider CAS login page
                    else:
                        logger.info(
                            (
                                "Got an invalid ticket %s from %s for service %s. "
                                "Retrying authentication"
                            ) % (
                                ticket,
                                auth.provider.server_url,
                                self.service_url
                            )
                        )
                        return HttpResponseRedirect(auth.get_login_url())
                # both xml.etree.ElementTree and lxml.etree exceptions inherit from SyntaxError
                except SyntaxError as error:
                    messages.add_message(
                        request,
                        messages.ERROR,
                        _(
                            u"Invalid response from your identity provider CAS upon "
                            u"ticket %(ticket)s validation: %(error)r"
                        ) % {'ticket': ticket, 'error': error}
                    )
                    response = redirect("cas_server:login")
                    response.delete_cookie("remember_provider")
                    return response
        except FederatedIendityProvider.DoesNotExist:
            logger.warning("Identity provider suffix %s not found" % provider)
            # if the identity provider is not found, redirect to the login page
            return redirect("cas_server:login")


class LoginView(View, LogoutMixin):
    """credential requestor / acceptor"""

    # pylint: disable=too-many-instance-attributes
    # Nine is reasonable in this case.

    #: The current :class:`models.User<cas_server.models.User>` object
    user = None
    #: The form to display to the user
    form = None

    #: current :class:`django.http.HttpRequest` object
    request = None
    #: service GET/POST parameter
    service = None
    #: ``True`` if renew GET/POST parameter is present and not "False"
    renew = None
    #: the warn GET/POST parameter
    warn = None
    #: the gateway GET/POST parameter
    gateway = None
    #: the method GET/POST parameter
    method = None

    #: ``True`` if the HTTP_X_AJAX http header is sent and ``settings.CAS_ENABLE_AJAX_AUTH``
    #: is ``True``, ``False`` otherwise.
    ajax = None

    #: ``True`` if the user has just authenticated
    renewed = False
    #: ``True`` if renew GET/POST parameter is present and not "False"
    warned = False

    #: The :class:`FederateAuth` transmited username (only used if ``settings.CAS_FEDERATE``
    #: is ``True``)
    username = None
    #: The :class:`FederateAuth` transmited ticket (only used if ``settings.CAS_FEDERATE`` is
    #: ``True``)
    ticket = None

    INVALID_LOGIN_TICKET = 1
    USER_LOGIN_OK = 2
    USER_LOGIN_FAILURE = 3
    USER_ALREADY_LOGGED = 4
    USER_AUTHENTICATED = 5
    USER_NOT_AUTHENTICATED = 6

    def init_post(self, request):
        """
            Initialize POST received parameters

            :param django.http.HttpRequest request: The current request object
        """
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
            # in federated mode, the valdated indentity provider CAS ticket is used as password
            self.ticket = request.POST.get('password')

    def gen_lt(self):
        """Generate a new LoginTicket and add it to the list of valid LT for the user"""
        self.request.session['lt'] = self.request.session.get('lt', []) + [utils.gen_lt()]
        if len(self.request.session['lt']) > 100:
            self.request.session['lt'] = self.request.session['lt'][-100:]

    def check_lt(self):
        """
            Check is the POSTed LoginTicket is valid, if yes invalide it

            :return: ``True`` if the LoginTicket is valid, ``False`` otherwise
            :rtype: bool
        """
        # save LT for later check
        lt_valid = self.request.session.get('lt', [])
        lt_send = self.request.POST.get('lt')
        # generate a new LT (by posting the LT has been consumed)
        self.gen_lt()
        # check if send LT is valid
        if lt_send not in lt_valid:
            return False
        else:
            self.request.session['lt'].remove(lt_send)
            # we need to redo the affectation for django to detect that the list has changed
            # and for its new value to be store in the session
            self.request.session['lt'] = self.request.session['lt']
            return True

    def post(self, request, *args, **kwargs):
        """
            method called on POST request on this view

            :param django.http.HttpRequest request: The current request object
        """
        # initialize class parameters
        self.init_post(request)
        # process the POST request
        ret = self.process_post()
        if ret == self.INVALID_LOGIN_TICKET:
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u"Invalid login ticket, please try to log in again")
            )
        elif ret == self.USER_LOGIN_OK:
            # On successful login, update the :class:`models.User<cas_server.models.User>` ``date``
            # attribute by saving it. (``auto_now=True``)
            self.user = models.User.objects.get_or_create(
                username=self.request.session['username'],
                session_key=self.request.session.session_key
            )[0]
            self.user.last_login = timezone.now()
            self.user.save()
        elif ret == self.USER_LOGIN_FAILURE:  # bad user login
            if settings.CAS_FEDERATE:
                self.ticket = None
                self.username = None
                self.init_form()
            # preserve valid LoginTickets from session flush
            lt = self.request.session.get('lt', [])
            # On login failure, flush the session
            self.logout()
            # restore valid LoginTickets
            self.request.session['lt'] = lt
        elif ret == self.USER_ALREADY_LOGGED:
            pass
        else:  # pragma: no cover (should no happen)
            raise EnvironmentError("invalid output for LoginView.process_post")
        # call the GET/POST common part
        response = self.common()
        if self.warn:
            utils.set_cookie(
                response,
                "warn",
                "on",
                10 * 365 * 24 * 3600
            )
        else:
            response.delete_cookie("warn")
        return response

    def process_post(self):
        """
            Analyse the POST request:

                * check that the LoginTicket is valid
                * check that the user sumited credentials are valid

            :return:
                * :attr:`INVALID_LOGIN_TICKET` if the POSTed LoginTicket is not valid
                * :attr:`USER_ALREADY_LOGGED` if the user is already logged and do no request
                  reauthentication.
                * :attr:`USER_LOGIN_FAILURE` if the user is not logged or request for
                  reauthentication and his credentials are not valid
                * :attr:`USER_LOGIN_OK` if the user is not logged or request for
                  reauthentication and his credentials are valid
            :rtype: int
        """
        if not self.check_lt():
            self.init_form(self.request.POST)
            logger.warning("Received an invalid login ticket")
            return self.INVALID_LOGIN_TICKET
        elif not self.request.session.get("authenticated") or self.renew:
            # authentication request receive, initialize the form to use
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
                logger.warning("A login attempt failed")
                return self.USER_LOGIN_FAILURE
        else:
            logger.warning("Received a login attempt for an already-active user")
            return self.USER_ALREADY_LOGGED

    def init_get(self, request):
        """
            Initialize GET received parameters

            :param django.http.HttpRequest request: The current request object
        """
        self.request = request
        self.service = request.GET.get('service')
        self.renew = bool(request.GET.get('renew') and request.GET['renew'] != "False")
        self.gateway = request.GET.get('gateway')
        self.method = request.GET.get('method')
        self.ajax = settings.CAS_ENABLE_AJAX_AUTH and 'HTTP_X_AJAX' in request.META
        self.warn = request.GET.get('warn')
        if settings.CAS_FEDERATE:
            # here username and ticket are fetch from the session after a redirection from
            # FederateAuth.get
            self.username = request.session.get("federate_username")
            self.ticket = request.session.get("federate_ticket")
            if self.username:
                del request.session["federate_username"]
            if self.ticket:
                del request.session["federate_ticket"]

    def get(self, request, *args, **kwargs):
        """
            method called on GET request on this view

            :param django.http.HttpRequest request: The current request object
        """
        # initialize class parameters
        self.init_get(request)
        # process the GET request
        self.process_get()
        # call the GET/POST common part
        return self.common()

    def process_get(self):
        """
            Analyse the GET request

            :return:
                * :attr:`USER_NOT_AUTHENTICATED` if the user is not authenticated or is requesting
                  for authentication renewal
                * :attr:`USER_AUTHENTICATED` if the user is authenticated and is not requesting
                  for authentication renewal
            :rtype: int
        """
        # generate a new LT
        self.gen_lt()
        if not self.request.session.get("authenticated") or self.renew:
            # authentication will be needed, initialize the form to use
            self.init_form()
            return self.USER_NOT_AUTHENTICATED
        return self.USER_AUTHENTICATED

    def init_form(self, values=None):
        """
            Initialization of the good form depending of POST and GET parameters

            :param django.http.QueryDict values: A POST or GET QueryDict
        """
        if values:
            values = values.copy()
            values['lt'] = self.request.session['lt'][-1]
        form_initial = {
            'service': self.service,
            'method': self.method,
            'warn': (
                self.warn or self.request.session.get("warn") or self.request.COOKIES.get('warn')
            ),
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
        """
            Perform login against a service

            :return:
                * The rendering of the ``settings.CAS_WARN_TEMPLATE`` if the user asked to be
                  warned before ticket emission and has not yep been warned.
                * The redirection to the service URL with a ticket GET parameter
                * The redirection to the service URL without a ticket if ticket generation failed
                  and the :attr:`gateway` attribute is set
                * The rendering of the ``settings.CAS_LOGGED_TEMPLATE`` template with some error
                  messages if the ticket generation failed (e.g: user not allowed).
            :rtype: django.http.HttpResponse
        """
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
                _(u'Service %(url)s not allowed.') % {'url': self.service}
            )
        except models.BadUsername:
            error = 2
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u"Username not allowed")
            )
        except models.BadFilter:
            error = 3
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u"User characteristics not allowed")
            )
        except models.UserFieldNotDefined:
            error = 4
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u"The attribute %(field)s is needed to use"
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
        """
            Processing authenticated users

            :return:
                * The returned value of :meth:`service_login` if :attr:`service` is defined
                * The rendering of ``settings.CAS_LOGGED_TEMPLATE`` otherwise
            :rtype: django.http.HttpResponse
        """
        # Try to get the current :class:`models.User<cas_server.models.User>` object for the current
        # session
        try:
            self.user = models.User.objects.get(
                username=self.request.session.get("username"),
                session_key=self.request.session.session_key
            )
        # if not found, flush the session and redirect to the login page
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

        # if login against a service
        if self.service:
            return self.service_login()
        # else display the logged template
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
        """
            Processing non authenticated users

            :return:
                * The rendering of ``settings.CAS_LOGIN_TEMPLATE`` with various messages
                  depending of GET/POST parameters
                * The redirection to :class:`FederateAuth` if ``settings.CAS_FEDERATE`` is ``True``
                  and the "remember my identity provider" cookie is found
            :rtype: django.http.HttpResponse
        """
        if self.service:
            try:
                service_pattern = ServicePattern.validate(self.service)
                if self.gateway and not self.ajax:
                    # clean messages before leaving django
                    list(messages.get_messages(self.request))
                    return HttpResponseRedirect(self.service)

                if settings.CAS_SHOW_SERVICE_MESSAGES:
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
                if settings.CAS_SHOW_SERVICE_MESSAGES:
                    messages.add_message(
                        self.request,
                        messages.ERROR,
                        _(u'Service %s not allowed') % self.service
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
                        self.request.COOKIES.get('remember_provider') and
                        FederatedIendityProvider.objects.filter(
                            suffix=self.request.COOKIES['remember_provider']
                        )
                    ):
                        params = utils.copy_params(self.request.GET)
                        url = utils.reverse_params(
                            "cas_server:federateAuth",
                            params=params,
                            kwargs=dict(provider=self.request.COOKIES['remember_provider'])
                        )
                        return HttpResponseRedirect(url)
                    else:
                        # if user is authenticated and auth renewal is requested, redirect directly
                        # to the user identity provider
                        if self.renew and self.request.session.get("authenticated"):
                            try:
                                user = FederatedUser.get_from_federated_username(
                                    self.request.session.get("username")
                                )
                                params = utils.copy_params(self.request.GET)
                                url = utils.reverse_params(
                                    "cas_server:federateAuth",
                                    params=params,
                                    kwargs=dict(provider=user.provider.suffix)
                                )
                                return HttpResponseRedirect(url)
                            # Should normally not happen: if the user is logged, it exists in the
                            # database.
                            except FederatedUser.DoesNotExist:  # pragma: no cover
                                pass
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
        """
            Common part execute uppon GET and POST request

            :return:
                * The returned value of :meth:`authenticated` if the user is authenticated and
                  not requesting for authentication or if the authentication has just been renewed
                * The returned value of :meth:`not_authenticated` otherwise
            :rtype: django.http.HttpResponse
        """
        # if authenticated and successfully renewed authentication if needed
        if self.request.session.get("authenticated") and (not self.renew or self.renewed):
            return self.authenticated()
        else:
            return self.not_authenticated()


class Auth(CsrfExemptView):
    """
        A simple view to validate username/password/service tuple

        csrf is disable as it is intended to be used by programs. Security is assured by a shared
        secret between the programs dans django-cas-server.
    """

    @staticmethod
    def post(request):
        """
            method called on POST request on this view

            :param django.http.HttpRequest request: The current request object
            :return: ``HttpResponse(u"yes\\n")`` if the POSTed tuple (username, password, service)
                if valid (i.e. (username, password) is valid dans username is allowed on service).
                ``HttpResponse(u"no\\n…")`` otherwise, with possibly an error message on the second
                line.
            :rtype: django.http.HttpResponse
        """
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
        """
            method called on GET request on this view

            :param django.http.HttpRequest request: The current request object
            :return:
                * ``HttpResponse("yes\\nusername")`` if submited (service, ticket) is valid
                * else ``HttpResponse("no\\n")``
            :rtype: django.http.HttpResponse
        """
        # store wanted GET parameters
        service = request.GET.get('service')
        ticket = request.GET.get('ticket')
        renew = True if request.GET.get('renew') else False
        # service and ticket parameters are mandatory
        if service and ticket:
            try:
                # search for the ticket, associated at service that is not yet validated but is
                # still valid
                ticket = ServiceTicket.get(ticket, renew, service)
                logger.info(
                    "Validate: Service ticket %s validated, user %s authenticated on service %s" % (
                        ticket.value,
                        ticket.user.username,
                        ticket.service
                    )
                )
                return HttpResponse(
                    u"yes\n%s\n" % ticket.username(),
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
class ValidationBaseError(Exception):
    """Base class for both saml and cas validation error"""

    #: The error code
    code = None
    #: The error message
    msg = None

    def __init__(self, code, msg=""):
        self.code = code
        self.msg = msg
        super(ValidationBaseError, self).__init__(code)

    def __str__(self):
        return u"%s" % self.msg

    def render(self, request):
        """
            render the error template for the exception

            :param django.http.HttpRequest request: The current request object:
            :return: the rendered ``cas_server/serviceValidateError.xml`` template
            :rtype: django.http.HttpResponse
        """
        return render(
            request,
            self.template,
            self.context(), content_type="text/xml; charset=utf-8"
        )


class ValidateError(ValidationBaseError):
    """handle service validation error"""

    #: template to be render for the error
    template = "cas_server/serviceValidateError.xml"

    def context(self):
        """
            content to use to render :attr:`template`

            :return: A dictionary to contextualize :attr:`template`
            :rtype: dict
        """
        return {'code': self.code, 'msg': self.msg}


class ValidateService(View):
    """service ticket validation [CAS 2.0] and [CAS 3.0]"""
    #: Current :class:`django.http.HttpRequest` object
    request = None
    #: The service GET parameter
    service = None
    #: the ticket GET parameter
    ticket = None
    #: the pgtUrl GET parameter
    pgt_url = None
    #: the renew GET parameter
    renew = None
    #: specify if ProxyTicket are allowed by the view. Hence we user the same view for
    #: ``/serviceValidate`` and ``/proxyValidate`` juste changing the parameter.
    allow_proxy_ticket = False

    def get(self, request):
        """
            method called on GET request on this view

            :param django.http.HttpRequest request: The current request object:
            :return: The rendering of ``cas_server/serviceValidate.xml`` if no errors is raised,
                the rendering or ``cas_server/serviceValidateError.xml`` otherwise.
            :rtype: django.http.HttpResponse
        """
        # define the class parameters
        self.request = request
        self.service = request.GET.get('service')
        self.ticket = request.GET.get('ticket')
        self.pgt_url = request.GET.get('pgtUrl')
        self.renew = True if request.GET.get('renew') else False

        # service and ticket parameter are mandatory
        if not self.service or not self.ticket:
            logger.warning("ValidateService: missing ticket or service")
            return ValidateError(
                u'INVALID_REQUEST',
                u"you must specify a service and a ticket"
            ).render(request)
        else:
            try:
                # search the ticket in the database
                self.ticket, proxies = self.process_ticket()
                # prepare template rendering context
                params = {
                    'username': self.ticket.username(),
                    'attributes': self.ticket.attributs_flat(),
                    'proxies': proxies,
                    'auth_date': self.ticket.user.last_login.replace(microsecond=0).isoformat(),
                    'is_new_login': 'true' if self.ticket.renew else 'false'
                }
                # if pgtUrl is set, require https or localhost
                if self.pgt_url and (
                    self.pgt_url.startswith("https://") or
                    re.match(r"^http://(127\.0\.0\.1|localhost)(:[0-9]+)?(/.*)?$", self.pgt_url)
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
        """
            fetch the ticket against the database and check its validity

            :raises ValidateError: if the ticket is not found or not valid, potentially for that
                service
            :returns: A couple (ticket, proxies list)
            :rtype: :obj:`tuple`
        """
        try:
            proxies = []
            if self.allow_proxy_ticket:
                ticket = models.Ticket.get(self.ticket, self.renew)
            else:
                ticket = models.ServiceTicket.get(self.ticket, self.renew)
            try:
                for prox in ticket.proxies.all():
                    proxies.append(prox.url)
            except AttributeError:
                pass
            if ticket.service != self.service:
                raise ValidateError(u'INVALID_SERVICE', self.service)
            return ticket, proxies
        except Ticket.DoesNotExist:
            raise ValidateError(u'INVALID_TICKET', self.ticket)
        except (ServiceTicket.DoesNotExist, ProxyTicket.DoesNotExist):
            raise ValidateError(u'INVALID_TICKET', 'ticket not found')

    def process_pgturl(self, params):
        """
            Handle PGT request

            :param dict params: A template context dict
            :raises ValidateError: if pgtUrl is invalid or if TLS validation of the pgtUrl fails
            :return: The rendering of ``cas_server/serviceValidate.xml``, using ``params``
            :rtype: django.http.HttpResponse
        """
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

    #: Current :class:`django.http.HttpRequest` object
    request = None
    #: A ProxyGrantingTicket from the pgt GET parameter
    pgt = None
    #: the targetService GET parameter
    target_service = None

    def get(self, request):
        """
            method called on GET request on this view

            :param django.http.HttpRequest request: The current request object:
            :return: The returned value of :meth:`process_proxy` if no error is raised,
                else the rendering of ``cas_server/serviceValidateError.xml``.
            :rtype: django.http.HttpResponse
        """
        self.request = request
        self.pgt = request.GET.get('pgt')
        self.target_service = request.GET.get('targetService')
        try:
            # pgt and targetService parameters are mandatory
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
        """
            handle PT request

            :raises ValidateError: if the PGT is not found, or the target service not allowed or
                the user not allowed on the tardet service.
            :return: The rendering of ``cas_server/proxy.xml``
            :rtype: django.http.HttpResponse
        """
        try:
            # is the target service allowed
            pattern = ServicePattern.validate(self.target_service)
            # to get a proxy ticket require that the service allow it
            if not pattern.proxy:
                raise ValidateError(
                    u'UNAUTHORIZED_SERVICE',
                    u'the service %s does not allow proxy tickets' % self.target_service
                )
            # is the proxy granting ticket valid
            ticket = ProxyGrantingTicket.get(self.pgt)
            # is the pgt user allowed on the target service
            pattern.check_user(ticket.user)
            pticket = ticket.user.get_ticket(
                ProxyTicket,
                self.target_service,
                pattern,
                renew=False
            )
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
        except (Ticket.DoesNotExist, ProxyGrantingTicket.DoesNotExist):
            raise ValidateError(u'INVALID_TICKET', u'PGT %s not found' % self.pgt)
        except ServicePattern.DoesNotExist:
            raise ValidateError(u'UNAUTHORIZED_SERVICE', self.target_service)
        except (models.BadUsername, models.BadFilter, models.UserFieldNotDefined):
            raise ValidateError(
                u'UNAUTHORIZED_USER',
                u'User %s not allowed on %s' % (ticket.user.username, self.target_service)
            )


class SamlValidateError(ValidationBaseError):
    """handle saml validation error"""

    #: template to be render for the error
    template = "cas_server/samlValidateError.xml"

    def context(self):
        """
            :return: A dictionary to contextualize :attr:`template`
            :rtype: dict
        """
        return {
            'code': self.code,
            'msg': self.msg,
            'IssueInstant': timezone.now().isoformat(),
            'ResponseID': utils.gen_saml_id()
        }


class SamlValidate(CsrfExemptView):
    """SAML ticket validation"""
    request = None
    target = None
    ticket = None
    root = None

    def post(self, request, *args, **kwargs):
        """
            method called on POST request on this view

            :param django.http.HttpRequest request: The current request object
            :return: the rendering of ``cas_server/samlValidate.xml`` if no error is raised,
                else the rendering of ``cas_server/samlValidateError.xml``.
            :rtype: django.http.HttpResponse
        """
        self.request = request
        self.target = request.GET.get('TARGET')
        self.root = etree.fromstring(request.body)
        try:
            self.ticket = self.process_ticket()
            expire_instant = (self.ticket.creation +
                              timedelta(seconds=self.ticket.VALIDITY)).isoformat()
            params = {
                'IssueInstant': timezone.now().isoformat(),
                'expireInstant': expire_instant,
                'Recipient': self.target,
                'ResponseID': utils.gen_saml_id(),
                'username': self.ticket.username(),
                'attributes': self.ticket.attributs_flat(),
                'auth_date': self.ticket.user.last_login.replace(microsecond=0).isoformat(),
                'is_new_login': 'true' if self.ticket.renew else 'false'

            }
            logger.info(
                "SamlValidate: ticket %s validated for user %s on service %s." % (
                    self.ticket.value,
                    self.ticket.user.username,
                    self.ticket.service
                )
            )
            logger.debug(
                "SamlValidate: User attributes are:\n%s" % pprint.pformat(self.ticket.attributs)
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
        """
            validate ticket from SAML XML body

            :raises: SamlValidateError: if the ticket is not found or not valid, or if we fail
                to parse the posted XML.
            :return: a ticket object
            :rtype: :class:`models.Ticket<cas_server.models.Ticket>`
        """
        try:
            auth_req = self.root.getchildren()[1].getchildren()[0]
            ticket = auth_req.getchildren()[0].text
            ticket = models.Ticket.get(ticket)
            if ticket.service != self.target:
                raise SamlValidateError(
                    u'AuthnFailed',
                    u'TARGET %s does not match ticket service' % self.target
                )
            return ticket
        except (IndexError, KeyError):
            raise SamlValidateError(u'VersionMismatch')
        except Ticket.DoesNotExist:
            raise SamlValidateError(
                    u'AuthnFailed',
                    u'ticket %s should begin with PT- or ST-' % ticket
            )
        except (ServiceTicket.DoesNotExist, ProxyTicket.DoesNotExist):
            raise SamlValidateError(u'AuthnFailed', u'ticket %s not found' % ticket)
