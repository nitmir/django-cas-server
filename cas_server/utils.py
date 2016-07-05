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
"""Some util function for the app"""
from .default_settings import settings

from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib import messages

import random
import string
import json
import hashlib
import crypt
import base64
import six

from importlib import import_module
from datetime import datetime, timedelta
from six.moves.urllib.parse import urlparse, urlunparse, parse_qsl, urlencode


def context(params):
    """Function that add somes variable to the context before template rendering"""
    params["settings"] = settings
    return params


def json_response(request, data):
    """Wrapper dumping `data` to a json and sending it to the user with an HttpResponse"""
    data["messages"] = []
    for msg in messages.get_messages(request):
        data["messages"].append({'message': msg.message, 'level': msg.level_tag})
    return HttpResponse(json.dumps(data), content_type="application/json")


def import_attr(path):
    """transform a python module.attr path to the attr"""
    if not isinstance(path, str):
        return path
    if "." not in path:
        ValueError("%r should be of the form `module.attr` and we just got `attr`" % path)
    module, attr = path.rsplit('.', 1)
    try:
        return getattr(import_module(module), attr)
    except ImportError:
        raise ImportError("Module %r not found" % module)
    except AttributeError:
        raise AttributeError("Module %r has not attribut %r" % (module, attr))


def redirect_params(url_name, params=None):
    """Redirect to `url_name` with `params` as querystring"""
    url = reverse(url_name)
    params = urlencode(params if params else {})
    return HttpResponseRedirect(url + "?%s" % params)


def reverse_params(url_name, params=None, **kwargs):
    """compule the reverse url or `url_name` and add GET parameters from `params` to it"""
    url = reverse(url_name, **kwargs)
    params = urlencode(params if params else {})
    if params:
        return url + "?%s" % params
    else:
        return url


def copy_params(get_or_post_params, ignore=None):
    """copy from a dictionnary like `get_or_post_params` ignoring keys in the set `ignore`"""
    if ignore is None:
        ignore = set()
    params = {}
    for key in get_or_post_params:
        if key not in ignore and get_or_post_params[key]:
            params[key] = get_or_post_params[key]
    return params


def set_cookie(response, key, value, max_age):
    """Set the cookie `key` on `response` with value `value` valid for `max_age` secondes"""
    expires = datetime.strftime(
        datetime.utcnow() + timedelta(seconds=max_age),
        "%a, %d-%b-%Y %H:%M:%S GMT"
    )
    response.set_cookie(
        key,
        value,
        max_age=max_age,
        expires=expires,
        domain=settings.SESSION_COOKIE_DOMAIN,
        secure=settings.SESSION_COOKIE_SECURE or None
    )


def get_current_url(request, ignore_params=None):
    """Giving a django request, return the current http url, possibly ignoring some GET params"""
    if ignore_params is None:
        ignore_params = set()
    protocol = 'https' if request.is_secure() else "http"
    service_url = "%s://%s%s" % (protocol, request.get_host(), request.path)
    if request.GET:
        params = copy_params(request.GET, ignore_params)
        if params:
            service_url += "?%s" % urlencode(params)
    return service_url


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
    # make the params order deterministic
    query = list(query.items())
    query.sort()
    url_query = urlencode(query)
    if not isinstance(url_query, bytes):  # pragma: no cover in python3 urlencode return an unicode
        url_query = url_query.encode("utf-8")
    url_parts[4] = url_query
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


def get_tuple(nuplet, index, default=None):
    """
        return the value in index `index` of the tuple `nuplet` if it exists,
        else return `default`
    """
    if nuplet is None:
        return default
    try:
        return nuplet[index]
    except IndexError:
        return default


def crypt_salt_is_valid(salt):
    """Return True is salt is valid has a crypt salt, False otherwise"""
    if len(salt) < 2:
        return False
    else:
        if salt[0] == '$':
            if salt[1] == '$':
                return False
            else:
                if '$' not in salt[1:]:
                    return False
                else:
                    hashed = crypt.crypt("", salt)
                    if not hashed or '$' not in hashed[1:]:
                        return False
                    else:
                        return True
        else:
            return True


class LdapHashUserPassword(object):
    """Please see https://tools.ietf.org/id/draft-stroeder-hashed-userpassword-values-01.html"""

    schemes_salt = {b"{SMD5}", b"{SSHA}", b"{SSHA256}", b"{SSHA384}", b"{SSHA512}", b"{CRYPT}"}
    schemes_nosalt = {b"{MD5}", b"{SHA}", b"{SHA256}", b"{SHA384}", b"{SHA512}"}

    _schemes_to_hash = {
        b"{SMD5}": hashlib.md5,
        b"{MD5}": hashlib.md5,
        b"{SSHA}": hashlib.sha1,
        b"{SHA}": hashlib.sha1,
        b"{SSHA256}": hashlib.sha256,
        b"{SHA256}": hashlib.sha256,
        b"{SSHA384}": hashlib.sha384,
        b"{SHA384}": hashlib.sha384,
        b"{SSHA512}": hashlib.sha512,
        b"{SHA512}": hashlib.sha512
    }

    _schemes_to_len = {
        b"{SMD5}": 16,
        b"{SSHA}": 20,
        b"{SSHA256}": 32,
        b"{SSHA384}": 48,
        b"{SSHA512}": 64,
    }

    class BadScheme(ValueError):
        """Error raised then the hash scheme is not in schemes_salt + schemes_nosalt"""
        pass

    class BadHash(ValueError):
        """Error raised then the hash is too short"""
        pass

    class BadSalt(ValueError):
        """Error raised then with the scheme {CRYPT} the salt is invalid"""
        pass

    @classmethod
    def _raise_bad_scheme(cls, scheme, valid, msg):
        """
            Raise BadScheme error for `scheme`, possible valid scheme are
            in `valid`, the error message is `msg`
        """
        valid_schemes = [s.decode() for s in valid]
        valid_schemes.sort()
        raise cls.BadScheme(msg % (scheme, u", ".join(valid_schemes)))

    @classmethod
    def _test_scheme(cls, scheme):
        """Test if a scheme is valide or raise BadScheme"""
        if scheme not in cls.schemes_salt and scheme not in cls.schemes_nosalt:
            cls._raise_bad_scheme(
                scheme,
                cls.schemes_salt | cls.schemes_nosalt,
                "The scheme %r is not valid. Valide schemes are %s."
            )

    @classmethod
    def _test_scheme_salt(cls, scheme):
        """Test if the scheme need a salt or raise BadScheme"""
        if scheme not in cls.schemes_salt:
            cls._raise_bad_scheme(
                scheme,
                cls.schemes_salt,
                "The scheme %r is only valid without a salt. Valide schemes with salt are %s."
            )

    @classmethod
    def _test_scheme_nosalt(cls, scheme):
        """Test if the scheme need no salt or raise BadScheme"""
        if scheme not in cls.schemes_nosalt:
            cls._raise_bad_scheme(
                scheme,
                cls.schemes_nosalt,
                "The scheme %r is only valid with a salt. Valide schemes without salt are %s."
            )

    @classmethod
    def hash(cls, scheme, password, salt=None, charset="utf8"):
        """
           Hash `password` with `scheme` using `salt`.
           This three variable beeing encoded in `charset`.
        """
        scheme = scheme.upper()
        cls._test_scheme(scheme)
        if salt is None or salt == b"":
            salt = b""
            cls._test_scheme_nosalt(scheme)
        else:
            cls._test_scheme_salt(scheme)
        try:
            return scheme + base64.b64encode(
                cls._schemes_to_hash[scheme](password + salt).digest() + salt
            )
        except KeyError:
            if six.PY3:
                password = password.decode(charset)
                salt = salt.decode(charset)
            if not crypt_salt_is_valid(salt):
                raise cls.BadSalt("System crypt implementation do not support the salt %r" % salt)
            hashed_password = crypt.crypt(password, salt)
            if six.PY3:
                hashed_password = hashed_password.encode(charset)
            return scheme + hashed_password

    @classmethod
    def get_scheme(cls, hashed_passord):
        """Return the scheme of `hashed_passord` or raise BadHash"""
        if not hashed_passord[0] == b'{'[0] or b'}' not in hashed_passord:
            raise cls.BadHash("%r should start with the scheme enclosed with { }" % hashed_passord)
        scheme = hashed_passord.split(b'}', 1)[0]
        scheme = scheme.upper() + b"}"
        return scheme

    @classmethod
    def get_salt(cls, hashed_passord):
        """Return the salt of `hashed_passord` possibly empty"""
        scheme = cls.get_scheme(hashed_passord)
        cls._test_scheme(scheme)
        if scheme in cls.schemes_nosalt:
            return b""
        elif scheme == b'{CRYPT}':
            return b'$'.join(hashed_passord.split(b'$', 3)[:-1])[len(scheme):]
        else:
            hashed_passord = base64.b64decode(hashed_passord[len(scheme):])
            if len(hashed_passord) < cls._schemes_to_len[scheme]:
                raise cls.BadHash("Hash too short for the scheme %s" % scheme)
            return hashed_passord[cls._schemes_to_len[scheme]:]


def check_password(method, password, hashed_password, charset):
    """
        Check that `password` match `hashed_password` using `method`,
        assuming the encoding is `charset`.
    """
    if not isinstance(password, six.binary_type):
        password = password.encode(charset)
    if not isinstance(hashed_password, six.binary_type):
        hashed_password = hashed_password.encode(charset)
    if method == "plain":
        return password == hashed_password
    elif method == "crypt":
        if hashed_password.startswith(b'$'):
            salt = b'$'.join(hashed_password.split(b'$', 3)[:-1])
        elif hashed_password.startswith(b'_'):  # pragma: no cover old BSD format not supported
            salt = hashed_password[:9]
        else:
            salt = hashed_password[:2]
        if six.PY3:
            password = password.decode(charset)
            salt = salt.decode(charset)
            hashed_password = hashed_password.decode(charset)
        if not crypt_salt_is_valid(salt):
            raise ValueError("System crypt implementation do not support the salt %r" % salt)
        crypted_password = crypt.crypt(password, salt)
        return crypted_password == hashed_password
    elif method == "ldap":
        scheme = LdapHashUserPassword.get_scheme(hashed_password)
        salt = LdapHashUserPassword.get_salt(hashed_password)
        return LdapHashUserPassword.hash(scheme, password, salt, charset=charset) == hashed_password
    elif (
       method.startswith("hex_") and
       method[4:] in {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}
    ):
        return getattr(
            hashlib,
            method[4:]
        )(password).hexdigest().encode("ascii") == hashed_password.lower()
    else:
        raise ValueError("Unknown password method check %r" % method)
