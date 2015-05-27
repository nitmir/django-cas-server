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

from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.conf import settings
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.utils.translation import ugettext as _
from django.core.urlresolvers import reverse
from django.utils import timezone

import requests
import urllib
from lxml import etree
from datetime import timedelta

from . import utils
from . import forms
from . import models

def _logout(request):
    """Clean sessions variables"""
    try:
        del request.session["authenticated"]
    except KeyError:
        pass
    try:
        del request.session["username"]
    except KeyError:
        pass
    try:
        del request.session["warn"]
    except KeyError:
        pass


def redirect_params(url_name, params=None):
    """Redirect to `url_name` with `params` as querystring"""
    url = reverse(url_name)
    params = urllib.urlencode(params if params else {})
    return HttpResponseRedirect(url + "?%s" % params)


def login(request):
    """credential requestor / acceptor"""
    user = None
    form = None
    service_pattern = None
    renewed = False
    warned = False
    if request.method == 'POST':
        service = request.POST.get('service')
        renew = True if request.POST.get('renew') else False
        gateway = request.POST.get('gateway')
        method = request.POST.get('method')

        if not request.session.get("authenticated") or renew:
            form = forms.UserCredential(
                request.POST,
                initial={'service':service, 'method':method, 'warn':request.session.get("warn")}
            )
            if form.is_valid():
                user = models.User.objects.get(username=form.cleaned_data['username'])
                request.session.set_expiry(0)
                request.session["username"] = form.cleaned_data['username']
                request.session["warn"] = True if form.cleaned_data.get("warn") else False
                request.session["authenticated"] = True
                renewed = True
                warned = True
            else:
                _logout(request)
    else:
        service = request.GET.get('service')
        renew = True if request.GET.get('renew') else False
        gateway = request.GET.get('gateway')
        method = request.GET.get('method')

        if not request.session.get("authenticated") or renew:
            form = forms.UserCredential(
                initial={'service':service, 'method':method, 'warn':request.session.get("warn")}
            )

    # if authenticated and successfully renewed authentication if needed
    if request.session.get("authenticated") and \
    request.session.get("username") and (not renew or renewed):
        try:
            user = models.User.objects.get(username=request.session["username"])
        except models.User.DoesNotExist:
            _logout(request)
            return redirect_params("login", params=dict(request.GET))

        # if login agains a service is requestest
        if service:
            try:
                # is the service allowed
                service_pattern = models.ServicePattern.validate(service)
                # is the current user allowed on this service
                service_pattern.check_user(user)
                # if the user has asked to be warned before any login to a service
                if request.session.get("warn", True) and not warned:
                    messages.add_message(
                        request,
                        messages.WARNING,
                        _(u"Authentication has been required by service %(name)s (%(url)s)") % \
                        {'name':service_pattern.name, 'url':service}
                    )
                    return render(
                        request,
                        settings.CAS_WARN_TEMPLATE,
                        {'service_ticket_url':user.get_service_url(
                            service,
                            service_pattern,
                            renew=renew
                        )}
                    )
                else:
                    # redirect, using method ?
                    return redirect(user.get_service_url(service, service_pattern, renew=renew))
            except models.ServicePattern.DoesNotExist:
                messages.add_message(
                    request,
                    messages.ERROR,
                    _(u'Service %(url)s non allowed.') % {'url' : service}
                )
            except models.BadUsername:
                messages.add_message(
                    request,
                    messages.ERROR,
                    _(u"Username non allowed")
                )
            except models.BadFilter:
                messages.add_message(
                    request,
                    messages.ERROR,
                    _(u"User charateristics non allowed")
                )
            except models.UserFieldNotDefined:
                messages.add_message(
                    request,
                    messages.ERROR,
                    _(u"The attribut %(field)s is needed to use" \
                       " that service") % {'field':service_pattern.user_field}
                )

            # if gateway is set and auth failed redirect to the service without authentication
            if gateway:
                list(messages.get_messages(request)) # clean messages before leaving the django app
                return redirect(service)

        return render(request, settings.CAS_LOGGED_TEMPLATE, {'session':request.session})
    else:
        if service:
            try:
                service_pattern = models.ServicePattern.validate(service)
                if gateway:
                    list(messages.get_messages(request)) # clean messages before leaving django
                    return redirect(service)
                if request.session.get("authenticated") and renew:
                    messages.add_message(
                        request,
                        messages.WARNING,
                        _(u"Authentication renewal required by service" \
                           " %(name)s (%(url)s).") % {'name':service_pattern.name, 'url':service}
                    )
                else:
                    messages.add_message(
                        request,
                        messages.WARNING,
                        _(u"Authentication required by service" \
                           " %(name)s (%(url)s).") % {'name':service_pattern.name, 'url':service}
                    )
            except models.ServicePattern.DoesNotExist:
                messages.add_message(
                    request,
                    messages.ERROR,
                    _(u'Service %s non allowed') % service
                )
        return render(request, settings.CAS_LOGIN_TEMPLATE, {'form':form})

def logout(request):
    """destroy CAS session (logout)"""
    service = request.GET.get('service')
    if request.session.get("authenticated"):
        user = models.User.objects.get(username=request.session["username"])
        user.logout(request)
        user.delete()
        _logout(request)
    # if service is set, redirect to service after logout
    if service:
        list(messages.get_messages(request)) # clean messages before leaving the django app
        return redirect(service)
    # else redirect to login page
    else:
        messages.add_message(request, messages.SUCCESS, _(u'Successfully logout'))
        return redirect("login")

def validate(request):
    """service ticket validation"""
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


def ps_validate(request, ticket_type=None):
    """factorization for serviceValidate and proxyValidate"""
    if ticket_type is None:
        ticket_type = ['ST']
    service = request.GET.get('service')
    ticket = request.GET.get('ticket')
    pgt_url = request.GET.get('pgtUrl')
    renew = True if request.GET.get('renew') else False
    if service and ticket:
        for typ in ticket_type:
            if ticket.startswith(typ):
                break
        else:
            return render(
                request,
                "cas_server/serviceValidateError.xml",
                {'code':'INVALID_TICKET'},
                content_type="text/xml; charset=utf-8"
            )
        try:
            proxies = []
            if ticket.startswith("ST"):
                ticket = models.ServiceTicket.objects.get(
                    value=ticket,
                    service=service,
                    validate=False,
                    renew=renew,
                    creation__gt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_VALIDITY))
                )
            elif ticket.startswith("PT"):
                ticket = models.ProxyTicket.objects.get(
                    value=ticket,
                    service=service,
                    validate=False,
                    renew=renew,
                    creation__gt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_VALIDITY))
                )
                for prox in ticket.proxies.all():
                    proxies.append(prox.url)
            ticket.validate = True
            ticket.save()
            attributes = []
            for key, value in ticket.attributs.items():
                if isinstance(value, list):
                    for elt in value:
                        attributes.append((key, elt))
                else:
                    attributes.append((key, value))
            params = {'username':ticket.user.username, 'attributes':attributes, 'proxies':proxies}
            if ticket.service_pattern.user_field and \
            ticket.user.attributs.get(ticket.service_pattern.user_field):
                params['username'] = ticket.user.attributs.get(ticket.service_pattern.user_field)
            if pgt_url and pgt_url.startswith("https://"):
                pattern = models.ServicePattern.validate(pgt_url)
                if pattern.proxy:
                    proxyid = models.gen_pgtiou()
                    pticket = models.ProxyGrantingTicket.objects.create(
                        user=ticket.user,
                        service=pgt_url,
                        service_pattern=pattern
                    )
                    url = utils.update_url(pgt_url, {'pgtIou':proxyid, 'pgtId':pticket.value})
                    try:
                        ret = requests.get(url, verify=settings.CAS_PROXY_CA_CERTIFICATE_PATH)
                        if ret.status_code == 200:
                            params['proxyGrantingTicket'] = proxyid
                        else:
                            pticket.delete()
                        return render(
                            request,
                            "cas_server/serviceValidate.xml",
                            params,
                            content_type="text/xml; charset=utf-8"
                        )
                    except requests.exceptions.SSLError:
                        return render(
                            request,
                            "cas_server/serviceValidateError.xml",
                            {'code':'INVALID_PROXY_CALLBACK'},
                            content_type="text/xml; charset=utf-8"
                        )
                else:
                    return render(
                        request,
                        "cas_server/serviceValidateError.xml",
                        {'code':'INVALID_PROXY_CALLBACK'},
                        content_type="text/xml; charset=utf-8"
                    )
            else:
                return render(
                    request,
                    "cas_server/serviceValidate.xml",
                    params,
                    content_type="text/xml; charset=utf-8"
                )
        except (models.ServiceTicket.DoesNotExist, models.ProxyTicket.DoesNotExist):
            return render(
                request,
                "cas_server/serviceValidateError.xml",
                {'code':'INVALID_TICKET'},
                content_type="text/xml; charset=utf-8"
            )
        except models.ServicePattern.DoesNotExist:
            return render(
                request,
                "cas_server/serviceValidateError.xml",
                {'code':'INVALID_TICKET'},
                content_type="text/xml; charset=utf-8"
            )
    else:
        return render(
            request,
            "cas_server/serviceValidateError.xml",
            {'code':'INVALID_REQUEST'},
            content_type="text/xml; charset=utf-8"
        )

def service_validate(request):
    """service ticket validation CAS 2.0 (also work for CAS 3.0)"""
    return ps_validate(request)
def proxy_validate(request):
    """service/proxy ticket validation CAS 2.0 (also work for CAS 3.0)"""
    return ps_validate(request, ["ST", "PT"])

def proxy(request):
    """proxy ticket service"""
    pgt = request.GET.get('pgt')
    target_service = request.GET.get('targetService')
    if pgt and target_service:
        try:
            # is the target service allowed
            pattern = models.ServicePattern.validate(target_service)
            # is the proxy granting ticket valid
            ticket = models.ProxyGrantingTicket.objects.get(
                value=pgt,
                creation__gt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_VALIDITY))
            )
            # is the pgt user allowed on the target service
            pattern.check_user(ticket.user)
            pticket = ticket.user.get_ticket(models.ProxyTicket, target_service, pattern, False)
            pticket.proxies.create(url=ticket.service)
            return render(
                request,
                "cas_server/proxy.xml",
                {'ticket':pticket.value},
                content_type="text/xml; charset=utf-8"
            )
        except models.ProxyGrantingTicket.DoesNotExist:
            return render(
                request,
                "cas_server/serviceValidateError.xml",
                {'code':'INVALID_TICKET'},
                content_type="text/xml; charset=utf-8"
            )
        except models.ServicePattern.DoesNotExist:
            return render(
                request,
                "cas_server/serviceValidateError.xml",
                {'code':'INVALID_TICKET'},
                content_type="text/xml; charset=utf-8"
            )
        except models.BadUsername:
            return render(
                request,
                "cas_server/serviceValidateError.xml",
                {'code':'INVALID_TICKET'},
                content_type="text/xml; charset=utf-8"
            )
        except models.BadFilter:
            return render(
                request,
                "cas_server/serviceValidateError.xml",
                {'code':'INVALID_TICKET'},
                content_type="text/xml; charset=utf-8"
            )
        except models.UserFieldNotDefined:
            return render(
                request,
                "cas_server/serviceValidateError.xml",
                {'code':'INVALID_TICKET'},
                content_type="text/xml; charset=utf-8"
            )
    else:
        return render(
            request,
            "cas_server/serviceValidateError.xml",
            {'code':'INVALID_REQUEST'},
            content_type="text/xml; charset=utf-8"
        )

def p3_service_validate(request):
    """service ticket validation CAS 3.0"""
    return service_validate(request)

def p3_proxy_validate(request):
    """service/proxy ticket validation CAS 3.0"""
    return proxy_validate(request)

@csrf_exempt
def saml_validate(request):
    """checks the validity of a Service Ticket by a SAML 1.1 request"""
    if request.method == 'POST':
        target = request.GET.get('TARGET')
        root = etree.fromstring(request.body)
        try:
            auth_req = root.getchildren()[1].getchildren()[0]
            issue_instant = auth_req.attrib['IssueInstant']
            request_id = auth_req.attrib['RequestID']
            ticket = auth_req.getchildren()[0].text
            ticket = models.ServiceTicket.objects.get(
                value=ticket,
                service=target,
                validate=False,
                creation__gt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_VALIDITY))
            )
            ticket.validate = True
            ticket.save()
            expire_instant = (ticket.creation + \
            timedelta(seconds=settings.CAS_TICKET_VALIDITY)).isoformat()
            attributes = []
            for key, value in ticket.attributs.items():
                if isinstance(value, list):
                    for elt in value:
                        attributes.append((key, elt))
                else:
                    attributes.append((key, value))
            params = {
                'IssueInstant':issue_instant,
                'expireInstant':expire_instant,
                'Recipient':target,
                'ResponseID':request_id,
                'username':ticket.user.username,
                'attributes':attributes
            }
            if ticket.service_pattern.user_field and \
            ticket.user.attributs.get(ticket.service_pattern.user_field):
                params['username'] = ticket.user.attributs.get(ticket.service_pattern.user_field)
            return render(
                request,
                "cas_server/samlValidate.xml",
                params,
                content_type="text/xml; charset=utf-8"
            )
        except IndexError:
            return render(
                request,
                "cas_server/samlValidateError.xml",
                {'code':'VersionMismatch'},
                content_type="text/xml; charset=utf-8"
            )
        except KeyError:
            return render(
                request,
                "cas_server/samlValidateError.xml",
                {'code':'VersionMismatch'},
                content_type="text/xml; charset=utf-8"
            )
        except models.ServiceTicket.DoesNotExist:
            return render(
                request,
                "cas_server/samlValidateError.xml",
                {'code':'AuthnFailed'},
                content_type="text/xml; charset=utf-8"
            )
    else:
        return redirect("login")
