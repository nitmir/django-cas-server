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
"""Some util function for the app"""
from .default_settings import settings

from django.utils.importlib import import_module
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib import messages

import random
import string
import json

try:
    from urlparse import urlparse, urlunparse, parse_qsl
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode


def JsonResponse(request, data):
    data["messages"] = []
    for msg in messages.get_messages(request):
        data["messages"].append({'message': msg.message, 'level': msg.level_tag})
    return HttpResponse(json.dumps(data), content_type="application/json")


def import_attr(path):
    """transform a python module.attr path to the attr"""
    if not isinstance(path, str):
        return string
    module, attr = path.rsplit('.', 1)
    return getattr(import_module(module), attr)


def redirect_params(url_name, params=None):
    """Redirect to `url_name` with `params` as querystring"""
    url = reverse(url_name)
    params = urlencode(params if params else {})
    return HttpResponseRedirect(url + "?%s" % params)


def reverse_params(url_name, params=None, **kwargs):
    url = reverse(url_name, **kwargs)
    params = urlencode(params if params else {})
    return url + "?%s" % params


def update_url(url, params):
    """update params in the `url` query string"""
    if not isinstance(url, bytes):
        url = url.encode('utf-8')
    for key, value in list(params.items()):
        if not isinstance(key, bytes):
            del params[key]
            key = key.encode('utf-8')
        if not isinstance(value, bytes):
            value = value.encode('utf-8')
        params[key] = value
    url_parts = list(urlparse(url))
    query = dict(parse_qsl(url_parts[4]))
    query.update(params)
    url_parts[4] = urlencode(query)
    for i in range(len(url_parts)):
        if not isinstance(url_parts[i], bytes):
            url_parts[i] = url_parts[i].encode('utf-8')
    return urlunparse(url_parts).decode('utf-8')


def unpack_nested_exception(error):
    """If exception are stacked, return the first one"""
    i = 0
    while True:
        if error.args[i:]:
            if isinstance(error.args[i], Exception):
                error = error.args[i]
                i = 0
            else:
                i += 1
        else:
            break
    return error


def _gen_ticket(prefix, lg=settings.CAS_TICKET_LEN):
    """Generate a ticket with prefix `prefix`"""
    return '%s-%s' % (
        prefix,
        ''.join(
            random.choice(
                string.ascii_letters + string.digits
            ) for _ in range(lg - len(prefix) - 1)
        )
    )


def gen_lt():
    """Generate a Service Ticket"""
    return _gen_ticket(settings.CAS_LOGIN_TICKET_PREFIX, settings.CAS_LT_LEN)


def gen_st():
    """Generate a Service Ticket"""
    return _gen_ticket(settings.CAS_SERVICE_TICKET_PREFIX, settings.CAS_ST_LEN)


def gen_pt():
    """Generate a Proxy Ticket"""
    return _gen_ticket(settings.CAS_PROXY_TICKET_PREFIX, settings.CAS_PT_LEN)


def gen_pgt():
    """Generate a Proxy Granting Ticket"""
    return _gen_ticket(settings.CAS_PROXY_GRANTING_TICKET_PREFIX, settings.CAS_PGT_LEN)


def gen_pgtiou():
    """Generate a Proxy Granting Ticket IOU"""
    return _gen_ticket(settings.CAS_PROXY_GRANTING_TICKET_IOU_PREFIX, settings.CAS_PGTIOU_LEN)


def gen_saml_id():
    """Generate an saml id"""
    return _gen_ticket('_')
