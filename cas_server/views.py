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
"""views for the app"""
from . import default_settings

default_settings.noop()

from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.conf import settings
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext as _
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from django.views.generic import View

import requests
from lxml import etree
from datetime import timedelta

from . import utils
from . import forms
from . import models

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
    def clean_session_variables(self):
        """Clean sessions variables"""
        try:
            del self.request.session["authenticated"]
        except KeyError:
            pass
        try:
            del self.request.session["username"]
        except KeyError:
            pass
        try:
            del self.request.session["warn"]
        except KeyError:
            pass

    def logout(self):
        """effectively destroy CAS session"""
        try:
            user = models.User.objects.get(username=self.request.session.get("username"))
            user.logout(self.request)
            user.delete()
        except models.User.DoesNotExist:
            pass
        finally:
            self.clean_session_variables()

class LogoutView(View, LogoutMixin):
    """destroy CAS session (logout) view"""

    request = None
    service = None

    def get(self, request, *args, **kwargs):
        """methode called on GET request on this view"""
        self.request = request
        self.service = request.GET.get('service')
        self.logout()
        # if service is set, redirect to service after logout
        if self.service:
            list(messages.get_messages(request)) # clean messages before leaving the django app
            return HttpResponseRedirect(self.service)
        # else redirect to login page
        else:
            messages.add_message(request, messages.SUCCESS, _(u'Successfully logout'))
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

    renewed = False
    warned = False

    def post(self, request, *args, **kwargs):
        """methode called on POST request on this view"""
        self.request = request
        self.service = request.POST.get('service')
        self.renew = True if request.POST.get('renew') else False
        self.gateway = request.POST.get('gateway')
        self.method = request.POST.get('method')

        if not request.session.get("authenticated") or self.renew:
            self.form = forms.UserCredential(
                request.POST,
                initial={
                    'service':self.service,
                    'method':self.method,
                    'warn':request.session.get("warn")
                }
            )
            if self.form.is_valid():
                self.user = models.User.objects.get(username=self.form.cleaned_data['username'])
                request.session.set_expiry(0)
                request.session["username"] = self.form.cleaned_data['username']
                request.session["warn"] = True if self.form.cleaned_data.get("warn") else False
                request.session["authenticated"] = True
                self.renewed = True
                self.warned = True
            else:
                self.logout()
        return self.common()

    def get(self, request, *args, **kwargs):
        """methode called on GET request on this view"""
        self.request = request
        self.service = request.GET.get('service')
        self.renew = True if request.GET.get('renew') else False
        self.gateway = request.GET.get('gateway')
        self.method = request.GET.get('method')

        if not request.session.get("authenticated") or self.renew:
            self.form = forms.UserCredential(
                initial={
                    'service':self.service,
                    'method':self.method,
                    'warn':request.session.get("warn")
                }
            )

        return self.common()

    def service_login(self):
        """Perform login agains a service"""
        try:
            # is the service allowed
            service_pattern = models.ServicePattern.validate(self.service)
            # is the current user allowed on this service
            service_pattern.check_user(self.user)
            # if the user has asked to be warned before any login to a service
            if self.request.session.get("warn", True) and not self.warned:
                messages.add_message(
                    self.request,
                    messages.WARNING,
                    _(u"Authentication has been required by service %(name)s (%(url)s)") % \
                    {'name':service_pattern.name, 'url':self.service}
                )
                return render(
                    self.request,
                    settings.CAS_WARN_TEMPLATE,
                    {'service_ticket_url':self.user.get_service_url(
                        self.service,
                        service_pattern,
                        renew=self.renew
                    )}
                )
            else:
                # redirect, using method ?
                return HttpResponseRedirect(
                    self.user.get_service_url(self.service, service_pattern, renew=self.renew)
                )
        except models.ServicePattern.DoesNotExist:
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u'Service %(url)s non allowed.') % {'url' : self.service}
            )
        except models.BadUsername:
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u"Username non allowed")
            )
        except models.BadFilter:
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u"User charateristics non allowed")
            )
        except models.UserFieldNotDefined:
            messages.add_message(
                self.request,
                messages.ERROR,
                _(u"The attribut %(field)s is needed to use" \
                   " that service") % {'field':service_pattern.user_field}
            )

        # if gateway is set and auth failed redirect to the service without authentication
        if self.gateway:
            list(messages.get_messages(self.request)) # clean messages before leaving django
            return HttpResponseRedirect(self.service)

        return render(self.request, settings.CAS_LOGGED_TEMPLATE, {'session':self.request.session})

    def authenticated(self):
        """Processing authenticated users"""
        try:
            self.user = models.User.objects.get(username=self.request.session.get("username"))
        except models.User.DoesNotExist:
            self.logout()
            return utils.redirect_params("cas_server:login", params=dict(self.request.GET))

        # if login agains a service is self.requestest
        if self.service:
            return self.service_login()
        else:
            return render(
                self.request,
                settings.CAS_LOGGED_TEMPLATE,
                {'session':self.request.session}
            )

    def not_authenticated(self):
        """Processing non authenticated users"""
        if self.service:
            try:
                service_pattern = models.ServicePattern.validate(self.service)
                if self.gateway:
                    list(messages.get_messages(self.request))# clean messages before leaving django
                    return HttpResponseRedirect(self.service)
                if self.request.session.get("authenticated") and self.renew:
                    messages.add_message(
                        self.request,
                        messages.WARNING,
                        _(u"Authentication renewal required by service %(name)s (%(url)s).") %
                        {'name':service_pattern.name, 'url':self.service}
                    )
                else:
                    messages.add_message(
                        self.request,
                        messages.WARNING,
                        _(u"Authentication required by service %(name)s (%(url)s).") %
                        {'name':service_pattern.name, 'url':self.service}
                    )
            except models.ServicePattern.DoesNotExist:
                messages.add_message(
                    self.request,
                    messages.ERROR,
                    _(u'Service %s non allowed') % self.service
                )
        return render(self.request, settings.CAS_LOGIN_TEMPLATE, {'form':self.form})

    def common(self):
        """Part execute uppon GET and POST request"""
        # if authenticated and successfully renewed authentication if needed
        if self.request.session.get("authenticated") and (not self.renew or self.renewed):
            return self.authenticated()
        else:
            return self.not_authenticated()

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
                ticket = models.ServiceTicket.objects.get(
                    value=ticket,
                    service=service,
                    validate=False,
                    renew=renew,
                    creation__gt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_VALIDITY))
                )
                ticket.validate = True
                ticket.save()
                return HttpResponse("yes\n", content_type="text/plain")
            except models.ServiceTicket.DoesNotExist:
                return HttpResponse("no\n", content_type="text/plain")
        else:
            return HttpResponse("no\n", content_type="text/plain")


class ValidateError(Exception):
    """handle service validation error"""
    def __init__(self, code, msg=""):
        self.code = code
        self.msg = msg
        super(ValidateError, self).__init__(code)

    def __unicode__(self):
        return u"%s" % self.msg

    def render(self, request):
        """render the error template for the exception"""
        return render(
            request,
            "cas_server/serviceValidateError.xml",
            {'code':self.code, 'msg':self.msg},
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
            return ValidateError(
                'INVALID_REQUEST',
                "you must specify a service and a ticket"
            ).render(request)
        else:
            try:
                self.ticket, proxies = self.process_ticket()
                params = {
                    'username':self.ticket.user.username,
                    'attributes':self.attributes(),
                    'proxies':proxies
                }
                if self.ticket.service_pattern.user_field and \
                self.ticket.user.attributs.get(self.ticket.service_pattern.user_field):
                    params['username'] = self.ticket.user.attributs.get(
                        self.ticket.service_pattern.user_field
                    )
                if self.pgt_url and self.pgt_url.startswith("https://"):
                    return self.process_pgturl(params)
                else:
                    return render(
                        request,
                        "cas_server/serviceValidate.xml",
                        params,
                        content_type="text/xml; charset=utf-8"
                    )
            except ValidateError as error:
                return error.render(request)


    def process_ticket(self):
        """fetch the ticket angains the database and check its validity"""
        try:
            proxies = []
            if self.ticket.startswith(models.ServiceTicket.PREFIX):
                ticket = models.ServiceTicket.objects.get(
                    value=self.ticket,
                    validate=False,
                    renew=self.renew,
                    creation__gt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_VALIDITY))
                )
            elif self.allow_proxy_ticket and self.ticket.startswith(models.ProxyTicket.PREFIX):
                ticket = models.ProxyTicket.objects.get(
                    value=self.ticket,
                    validate=False,
                    renew=self.renew,
                    creation__gt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_VALIDITY))
                )
                for prox in ticket.proxies.all():
                    proxies.append(prox.url)
            else:
                raise ValidateError('INVALID_TICKET')
            ticket.validate = True
            ticket.save()
            if ticket.service != self.service:
                raise ValidateError('INVALID_SERVICE')
            return ticket, proxies
        except (models.ServiceTicket.DoesNotExist, models.ProxyTicket.DoesNotExist):
            raise ValidateError('INVALID_TICKET', 'ticket not found')


    def process_pgturl(self, params):
        """Handle PGT request"""
        try:
            pattern = models.ServicePattern.validate(self.pgt_url)
            if pattern.proxy_callback:
                proxyid = utils.gen_pgtiou()
                pticket = models.ProxyGrantingTicket.objects.create(
                    user=self.ticket.user,
                    service=self.pgt_url,
                    service_pattern=pattern,
                    single_log_out=pattern.single_log_out
                )
                url = utils.update_url(self.pgt_url, {'pgtIou':proxyid, 'pgtId':pticket.value})
                try:
                    ret = requests.get(url, verify=settings.CAS_PROXY_CA_CERTIFICATE_PATH)
                    if ret.status_code == 200:
                        params['proxyGrantingTicket'] = proxyid
                    else:
                        pticket.delete()
                    return render(
                        self.request,
                        "cas_server/serviceValidate.xml",
                        params,
                        content_type="text/xml; charset=utf-8"
                    )
                except requests.exceptions.SSLError as error:
                    error = utils.unpack_nested_exception(error)
                    raise ValidateError('INVALID_PROXY_CALLBACK', str(error))
            else:
                raise ValidateError(
                    'INVALID_PROXY_CALLBACK',
                    "callback url not allowed by configuration"
                )
        except models.ServicePattern.DoesNotExist:
            raise ValidateError(
                'INVALID_PROXY_CALLBACK',
                'callback url not allowed by configuration'
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
                    'INVALID_REQUEST',
                    "you must specify and pgt and targetService"
                )
        except ValidateError as error:
            return error.render(request)


    def process_proxy(self):
        """handle PT request"""
        try:
            # is the target service allowed
            pattern = models.ServicePattern.validate(self.target_service)
            if not pattern.proxy:
                raise ValidateError(
                    'UNAUTHORIZED_SERVICE',
                    'the service do not allow proxy ticket'
                )
            # is the proxy granting ticket valid
            ticket = models.ProxyGrantingTicket.objects.get(
                value=self.pgt,
                creation__gt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_VALIDITY))
            )
            # is the pgt user allowed on the target service
            pattern.check_user(ticket.user)
            pticket = ticket.user.get_ticket(
                models.ProxyTicket,
                self.target_service,
                pattern,
                renew=False)
            pticket.proxies.create(url=ticket.service)
            return render(
                self.request,
                "cas_server/proxy.xml",
                {'ticket':pticket.value},
                content_type="text/xml; charset=utf-8"
            )
        except models.ProxyGrantingTicket.DoesNotExist:
            raise ValidateError('INVALID_TICKET', 'PGT not found')
        except models.ServicePattern.DoesNotExist:
            raise ValidateError('UNAUTHORIZED_SERVICE')
        except (models.BadUsername, models.BadFilter, models.UserFieldNotDefined):
            raise ValidateError(
                'UNAUTHORIZED_USER',
                '%s not allowed on %s' % (ticket.user, self.target_service)
            )



class SamlValidateError(Exception):
    """handle saml validation error"""
    def __init__(self, code, msg=""):
        self.code = code
        self.msg = msg
        super(SamlValidateError, self).__init__(code)

    def __unicode__(self):
        return u"%s" % self.msg

    def render(self, request):
        """render the error template for the exception"""
        return render(
            request,
            "cas_server/samlValidateError.xml",
            {
                'code':self.code,
                'msg':self.msg,
                'IssueInstant':timezone.now().isoformat(),
                'ResponseID':utils.gen_saml_id()
            },
            content_type="text/xml; charset=utf-8"
        )

def _saml_validate_error(request, code, msg=""):
    """render the samlValidateError.xml templace using `code` and `msg`"""
    return render(
        request,
        "cas_server/samlValidateError.xml",
        {
            'code':code,
            'msg':msg,
            'IssueInstant':timezone.now().isoformat(),
            'ResponseID':utils.gen_saml_id()
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
            expire_instant = (self.ticket.creation + \
            timedelta(seconds=settings.CAS_TICKET_VALIDITY)).isoformat()
            attributes = self.attributes()
            params = {
                'IssueInstant':timezone.now().isoformat(),
                'expireInstant':expire_instant,
                'Recipient':self.target,
                'ResponseID':utils.gen_saml_id(),
                'username':self.ticket.user.username,
                'attributes':attributes
            }
            if self.ticket.service_pattern.user_field and \
            self.ticket.user.attributs.get(self.ticket.service_pattern.user_field):
                params['username'] = self.ticket.user.attributs.get(
                    self.ticket.service_pattern.user_field
                )
            return render(
                request,
                "cas_server/samlValidate.xml",
                params,
                content_type="text/xml; charset=utf-8"
            )
        except SamlValidateError as error:
            return error.render(request)

    def process_ticket(self):
        """validate ticket from SAML XML body"""
        try:
            auth_req = self.root.getchildren()[1].getchildren()[0]
            ticket = auth_req.getchildren()[0].text
            if ticket.startswith(models.ServiceTicket.PREFIX):
                ticket = models.ServiceTicket.objects.get(
                    value=ticket,
                    validate=False,
                    creation__gt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_VALIDITY))
                )
            elif ticket.startswith(models.ProxyTicket.PREFIX):
                ticket = models.ProxyTicket.objects.get(
                    value=ticket,
                    validate=False,
                    creation__gt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_VALIDITY))
                )
            else:
                raise SamlValidateError(
                    'AuthnFailed',
                    'ticket should begin with PT- or ST-'
                )
            ticket.validate = True
            ticket.save()
            if ticket.service != self.target:
                raise SamlValidateError(
                    'AuthnFailed',
                    'TARGET do not match ticket service'
                )
            return ticket
        except (IndexError, KeyError):
            raise SamlValidateError('VersionMismatch')
        except (models.ServiceTicket.DoesNotExist, models.ProxyTicket.DoesNotExist):
            raise SamlValidateError('AuthnFailed', 'ticket not found')
