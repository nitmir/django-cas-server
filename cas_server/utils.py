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

from django.http import HttpResponseRedirect, HttpResponse
from django.contrib import messages
from django.contrib.messages import constants as DEFAULT_MESSAGE_LEVELS
from django.core.serializers.json import DjangoJSONEncoder
from django.utils import timezone
from django.core.exceptions import ValidationError
try:
    from django.urls import reverse
    from django.utils.translation import gettext_lazy as _
except ImportError:
    from django.core.urlresolvers import reverse
    from django.utils.translation import ugettext_lazy as _

import re
import random
import string
import json
import hashlib
import crypt
import base64
import six
import requests
import time
import logging
import binascii

from importlib import import_module
from datetime import datetime, timedelta
from six.moves.urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from . import VERSION

#: logger facility
logger = logging.getLogger(__name__)


def json_encode(obj):
    """Encode a python object to json"""
    try:
        return json_encode.encoder.encode(obj)
    except AttributeError:
        json_encode.encoder = DjangoJSONEncoder(default=six.text_type)
        return json_encode(obj)


def context(params):
    """
        Function that add somes variable to the context before template rendering

        :param dict params: The context dictionary used to render templates.
        :return: The ``params`` dictionary with the key ``settings`` set to
            :obj:`django.conf.settings`.
        :rtype: dict
    """
    params["settings"] = settings
    params["message_levels"] = DEFAULT_MESSAGE_LEVELS

    if settings.CAS_NEW_VERSION_HTML_WARNING:
        LAST_VERSION = last_version()
        params["VERSION"] = VERSION
        params["LAST_VERSION"] = LAST_VERSION
        if LAST_VERSION is not None:
            params["upgrade_available"] = decode_version(VERSION) < decode_version(LAST_VERSION)
        else:
            params["upgrade_available"] = False

    if settings.CAS_INFO_MESSAGES_ORDER:
        params["CAS_INFO_RENDER"] = []
        for msg_name in settings.CAS_INFO_MESSAGES_ORDER:
            if msg_name in settings.CAS_INFO_MESSAGES:
                if not isinstance(settings.CAS_INFO_MESSAGES[msg_name], dict):
                    continue
                msg = settings.CAS_INFO_MESSAGES[msg_name].copy()
                if "message" in msg:
                    msg["name"] = msg_name
                    # use info as default infox type
                    msg["type"] = msg.get("type", "info")
                    # make box discardable by default
                    msg["discardable"] = msg.get("discardable", True)
                    msg_hash = (
                        six.text_type(msg["message"]).encode("utf-8") +
                        msg["type"].encode("utf-8")
                    )
                    # hash depend of the rendering language
                    msg["hash"] = hashlib.md5(msg_hash).hexdigest()
                    params["CAS_INFO_RENDER"].append(msg)
    return params


def json_response(request, data):
    """
        Wrapper dumping `data` to a json and sending it to the user with an HttpResponse

        :param django.http.HttpRequest request: The request object used to generate this response.
        :param dict data: The python dictionnary to return as a json
        :return: The content of ``data`` serialized in json
        :rtype: django.http.HttpResponse
    """
    data["messages"] = []
    for msg in messages.get_messages(request):
        data["messages"].append({'message': msg.message, 'level': msg.level_tag})
    return HttpResponse(json.dumps(data), content_type="application/json")


def import_attr(path):
    """
        transform a python dotted path to the attr

        :param path: A dotted path to a python object or a python object
        :type path: :obj:`unicode` or :obj:`str` or anything
        :return: The python object pointed by the dotted path or the python object unchanged
    """
    # if we got a str, decode it to unicode (normally it should only contain ascii)
    if isinstance(path, six.binary_type):
        path = path.decode("utf-8")
    # if path is not an unicode, return it unchanged (may be it is already the attribute to import)
    if not isinstance(path, six.text_type):
        return path
    if u"." not in path:
        ValueError("%r should be of the form `module.attr` and we just got `attr`" % path)
    module, attr = path.rsplit(u'.', 1)
    try:
        return getattr(import_module(module), attr)
    except ImportError:
        raise ImportError("Module %r not found" % module)
    except AttributeError:
        raise AttributeError("Module %r has not attribut %r" % (module, attr))


def redirect_params(url_name, params=None):
    """
        Redirect to ``url_name`` with ``params`` as querystring

        :param unicode url_name: a URL pattern name
        :param params: Some parameter to append to the reversed URL
        :type params: :obj:`dict` or :obj:`NoneType<types.NoneType>`
        :return: A redirection to the URL with name ``url_name`` with ``params`` as querystring.
        :rtype: django.http.HttpResponseRedirect
    """
    url = reverse(url_name)
    params = urlencode(params if params else {})
    return HttpResponseRedirect(url + "?%s" % params)


def reverse_params(url_name, params=None, **kwargs):
    """
        compute the reverse url of ``url_name`` and add to it parameters from ``params``
        as querystring

        :param unicode url_name: a URL pattern name
        :param params: Some parameter to append to the reversed URL
        :type params: :obj:`dict` or :obj:`NoneType<types.NoneType>`
        :param **kwargs: additional parameters needed to compure the reverse URL
        :return: The computed reverse URL of ``url_name`` with possible querystring from ``params``
        :rtype: unicode
    """
    url = reverse(url_name, **kwargs)
    params = urlencode(params if params else {})
    if params:
        return u"%s?%s" % (url, params)
    else:
        return url


def copy_params(get_or_post_params, ignore=None):
    """
        copy a :class:`django.http.QueryDict` in a :obj:`dict` ignoring keys in the set ``ignore``

        :param django.http.QueryDict get_or_post_params: A GET or POST
            :class:`QueryDict<django.http.QueryDict>`
        :param set ignore: An optinal set of keys to ignore during the copy
        :return: A copy of get_or_post_params
        :rtype: dict
    """
    if ignore is None:
        ignore = set()
    params = {}
    for key in get_or_post_params:
        if key not in ignore and get_or_post_params[key]:
            params[key] = get_or_post_params[key]
    return params


def set_cookie(response, key, value, max_age):
    """
        Set the cookie ``key`` on ``response`` with value ``value`` valid for ``max_age`` secondes

        :param django.http.HttpResponse response: a django response where to set the cookie
        :param unicode key: the cookie key
        :param unicode value: the cookie value
        :param int max_age: the maximum validity age of the cookie
    """
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
    """
        Giving a django request, return the current http url, possibly ignoring some GET parameters

        :param django.http.HttpRequest request: The current request object.
        :param set ignore_params: An optional set of GET parameters to ignore
        :return: The URL of the current page, possibly omitting some parameters from
            ``ignore_params`` in the querystring.
        :rtype: unicode
    """
    if ignore_params is None:
        ignore_params = set()
    protocol = u'https' if request.is_secure() else u"http"
    service_url = u"%s://%s%s" % (protocol, request.get_host(), request.path)
    if request.GET:
        params = copy_params(request.GET, ignore_params)
        if params:
            service_url += u"?%s" % urlencode(params)
    return service_url


def update_url(url, params):
    """
        update parameters using ``params`` in the ``url`` query string

        :param url: An URL possibily with a querystring
        :type url: :obj:`unicode` or :obj:`str`
        :param dict params: A dictionary of parameters for updating the url querystring
        :return: The URL with an updated querystring
        :rtype: unicode
    """
    def to_unicode(data):
        if isinstance(data, bytes):
            return data.decode('utf-8')
        else:
            return data

    def to_bytes(data):
        if not isinstance(data, bytes):
            return data.encode('utf-8')
        else:
            return data

    if six.PY3:
        url = to_unicode(url)
        params = {to_unicode(key): to_unicode(value) for (key, value) in params.items()}
    else:
        url = to_bytes(url)
        params = {to_bytes(key): to_bytes(value) for (key, value) in params.items()}

    url_parts = list(urlparse(url))
    query = dict(parse_qsl(url_parts[4], keep_blank_values=True))
    query.update(params)
    # make the params order deterministic
    query = list(query.items())
    query.sort()
    url_query = urlencode(query)
    url_parts[4] = url_query
    url = urlunparse(url_parts)

    if isinstance(url, bytes):
        url = url.decode('utf-8')
    return url


def unpack_nested_exception(error):
    """
        If exception are stacked, return the first one

        :param error: A python exception with possible exception embeded within
        :return: A python exception with no exception embeded within
    """
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


def _gen_ticket(prefix=None, lg=settings.CAS_TICKET_LEN):
    """
        Generate a ticket with prefix ``prefix`` and length ``lg``

        :param unicode prefix: An optional prefix (probably ST, PT, PGT or PGTIOU)
        :param int lg: The length of the generated ticket (with the prefix)
        :return: A randomlly generated ticket of length ``lg``
        :rtype: unicode
    """
    random_part = u''.join(
        random.choice(
            string.ascii_letters + string.digits
        ) for _ in range(lg - len(prefix or "") - 1)
    )
    if prefix is not None:
        return u'%s-%s' % (prefix, random_part)
    else:
        return random_part


def gen_lt():
    """
        Generate a Login Ticket

        :return: A ticket with prefix ``settings.CAS_LOGIN_TICKET_PREFIX`` and length
            ``settings.CAS_LT_LEN``
        :rtype: unicode
    """
    return _gen_ticket(settings.CAS_LOGIN_TICKET_PREFIX, settings.CAS_LT_LEN)


def gen_st():
    """
        Generate a Service Ticket

        :return: A ticket with prefix ``settings.CAS_SERVICE_TICKET_PREFIX`` and length
            ``settings.CAS_ST_LEN``
        :rtype: unicode
    """
    return _gen_ticket(settings.CAS_SERVICE_TICKET_PREFIX, settings.CAS_ST_LEN)


def gen_pt():
    """
        Generate a Proxy Ticket

        :return: A ticket with prefix ``settings.CAS_PROXY_TICKET_PREFIX`` and length
            ``settings.CAS_PT_LEN``
        :rtype: unicode
    """
    return _gen_ticket(settings.CAS_PROXY_TICKET_PREFIX, settings.CAS_PT_LEN)


def gen_pgt():
    """
        Generate a Proxy Granting Ticket

        :return: A ticket with prefix ``settings.CAS_PROXY_GRANTING_TICKET_PREFIX`` and length
            ``settings.CAS_PGT_LEN``
        :rtype: unicode
    """
    return _gen_ticket(settings.CAS_PROXY_GRANTING_TICKET_PREFIX, settings.CAS_PGT_LEN)


def gen_pgtiou():
    """
        Generate a Proxy Granting Ticket IOU

        :return: A ticket with prefix ``settings.CAS_PROXY_GRANTING_TICKET_IOU_PREFIX`` and length
            ``settings.CAS_PGTIOU_LEN``
        :rtype: unicode
    """
    return _gen_ticket(settings.CAS_PROXY_GRANTING_TICKET_IOU_PREFIX, settings.CAS_PGTIOU_LEN)


def gen_saml_id():
    """
        Generate an saml id

        :return: A random id of length ``settings.CAS_TICKET_LEN``
        :rtype: unicode
    """
    return _gen_ticket()


def get_tuple(nuplet, index, default=None):
    """
        :param tuple nuplet: A tuple
        :param int index: An index
        :param default: An optional default value
        :return: ``nuplet[index]`` if defined, else ``default`` (possibly ``None``)
    """
    if nuplet is None:
        return default
    try:
        return nuplet[index]
    except IndexError:
        return default


def crypt_salt_is_valid(salt):
    """
        Validate a salt as crypt salt

        :param str salt: a password salt
        :return: ``True`` if ``salt`` is a valid crypt salt on this system, ``False`` otherwise
        :rtype: bool
    """
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
                    try:
                        hashed = crypt.crypt("", salt)
                    except OSError:
                        return False
                    if not hashed or '$' not in hashed[1:]:
                        return False
                    else:
                        return True
        else:
            return True


class LdapHashUserPassword(object):
    """
        Class to deal with hashed password as defined at
        https://tools.ietf.org/id/draft-stroeder-hashed-userpassword-values-01.html
    """

    #: valide schemes that require a salt
    schemes_salt = {b"{SMD5}", b"{SSHA}", b"{SSHA256}", b"{SSHA384}", b"{SSHA512}", b"{CRYPT}"}
    #: valide sschemes that require no slat
    schemes_nosalt = {b"{MD5}", b"{SHA}", b"{SHA256}", b"{SHA384}", b"{SHA512}"}

    #: map beetween scheme and hash function
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

    #: map between scheme and hash length
    _schemes_to_len = {
        b"{SMD5}": 16,
        b"{SSHA}": 20,
        b"{SSHA256}": 32,
        b"{SSHA384}": 48,
        b"{SSHA512}": 64,
    }

    class BadScheme(ValueError):
        """
            Error raised then the hash scheme is not in
            :attr:`LdapHashUserPassword.schemes_salt` + :attr:`LdapHashUserPassword.schemes_nosalt`
        """
        pass

    class BadHash(ValueError):
        """Error raised then the hash is too short"""
        pass

    class BadSalt(ValueError):
        """Error raised then, with the scheme ``{CRYPT}``, the salt is invalid"""
        pass

    @classmethod
    def _raise_bad_scheme(cls, scheme, valid, msg):
        """
            Raise :attr:`BadScheme` error for ``scheme``, possible valid scheme are
            in ``valid``, the error message is ``msg``

            :param bytes scheme: A bad scheme
            :param list valid: A list a valid scheme
            :param str msg: The error template message
            :raises LdapHashUserPassword.BadScheme: always
        """
        valid_schemes = [s.decode() for s in valid]
        valid_schemes.sort()
        raise cls.BadScheme(msg % (scheme, u", ".join(valid_schemes)))

    @classmethod
    def _test_scheme(cls, scheme):
        """
            Test if a scheme is valide or raise BadScheme

            :param bytes scheme: A scheme
            :raises BadScheme: if ``scheme`` is not a valid scheme
        """
        if scheme not in cls.schemes_salt and scheme not in cls.schemes_nosalt:
            cls._raise_bad_scheme(
                scheme,
                cls.schemes_salt | cls.schemes_nosalt,
                "The scheme %r is not valid. Valide schemes are %s."
            )

    @classmethod
    def _test_scheme_salt(cls, scheme):
        """
            Test if the scheme need a salt or raise BadScheme

            :param bytes scheme: A scheme
            :raises BadScheme: if ``scheme` require no salt
        """
        if scheme not in cls.schemes_salt:
            cls._raise_bad_scheme(
                scheme,
                cls.schemes_salt,
                "The scheme %r is only valid without a salt. Valide schemes with salt are %s."
            )

    @classmethod
    def _test_scheme_nosalt(cls, scheme):
        """
            Test if the scheme need no salt or raise BadScheme

            :param bytes scheme: A scheme
            :raises BadScheme: if ``scheme` require a salt
        """
        if scheme not in cls.schemes_nosalt:
            cls._raise_bad_scheme(
                scheme,
                cls.schemes_nosalt,
                "The scheme %r is only valid with a salt. Valide schemes without salt are %s."
            )

    @classmethod
    def hash(cls, scheme, password, salt=None, charset="utf8"):
        """
           Hash ``password`` with ``scheme`` using ``salt``.
           This three variable beeing encoded in ``charset``.

           :param bytes scheme: A valid scheme
           :param bytes password: A byte string to hash using ``scheme``
           :param bytes salt: An optional salt to use if ``scheme`` requires any
           :param str charset: The encoding of ``scheme``, ``password`` and ``salt``
           :return: The hashed password encoded with ``charset``
           :rtype: bytes
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
        """
            Return the scheme of ``hashed_passord`` or raise :attr:`BadHash`

            :param bytes hashed_passord: A hashed password
            :return: The scheme used by the hashed password
            :rtype: bytes
            :raises BadHash: if no valid scheme is found within ``hashed_passord``
        """
        if not hashed_passord[0] == b'{'[0] or b'}' not in hashed_passord:
            raise cls.BadHash("%r should start with the scheme enclosed with { }" % hashed_passord)
        scheme = hashed_passord.split(b'}', 1)[0]
        scheme = scheme.upper() + b"}"
        return scheme

    @classmethod
    def get_salt(cls, hashed_passord):
        """
            Return the salt of ``hashed_passord`` possibly empty

            :param bytes hashed_passord: A hashed password
            :return: The salt used by the hashed password (empty if no salt is used)
            :rtype: bytes
            :raises BadHash: if no valid scheme is found within ``hashed_passord`` or if the
                hashed password is too short for the scheme found.
        """
        scheme = cls.get_scheme(hashed_passord)
        cls._test_scheme(scheme)
        if scheme in cls.schemes_nosalt:
            return b""
        elif scheme == b'{CRYPT}':
            if b'$' in hashed_passord:
                return b'$'.join(hashed_passord.split(b'$', 3)[:-1])[len(scheme):]
            return hashed_passord.split(b'}', 1)[-1]
        else:
            try:
                hashed_passord = base64.b64decode(hashed_passord[len(scheme):])
            except (TypeError, binascii.Error) as error:
                raise cls.BadHash("Bad base64: %s" % error)
            if len(hashed_passord) < cls._schemes_to_len[scheme]:
                raise cls.BadHash("Hash too short for the scheme %s" % scheme)
            return hashed_passord[cls._schemes_to_len[scheme]:]


def check_password(method, password, hashed_password, charset):
    """
        Check that ``password`` match `hashed_password` using ``method``,
        assuming the encoding is ``charset``.

        :param str method: on of ``"crypt"``, ``"ldap"``, ``"hex_md5"``, ``"hex_sha1"``,
            ``"hex_sha224"``, ``"hex_sha256"``, ``"hex_sha384"``, ``"hex_sha512"``, ``"plain"``
        :param password: The user inputed password
        :type password: :obj:`str` or :obj:`unicode`
        :param hashed_password: The hashed password as stored in the database
        :type hashed_password: :obj:`str` or :obj:`unicode`
        :param str charset: The used char encoding (also used internally, so it must be valid for
            the charset used by ``password`` when it was initially )
        :return: True if ``password`` match ``hashed_password`` using ``method``,
            ``False`` otherwise
        :rtype: bool
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


def decode_version(version):
    """
        decode a version string following version semantic http://semver.org/ input a tuple of int.
        It will work as long as we do not use pre release versions.

        :param unicode version: A dotted version
        :return: A tuple a int
        :rtype: tuple
    """
    return tuple(int(sub_version) for sub_version in version.split('.'))


def last_version():
    """
        Fetch the last version from pypi and return it. On successful fetch from pypi, the response
        is cached 24h, on error, it is cached 10 min.

        :return: the last django-cas-server version
        :rtype: unicode
    """
    try:
        last_update, version, success = last_version._cache
    except AttributeError:
        last_update = 0
        version = None
        success = False
    cache_delta = 24 * 3600 if success else 600
    if (time.time() - last_update) < cache_delta:
        return version
    else:
        try:
            req = requests.get(settings.CAS_NEW_VERSION_JSON_URL)
            data = json.loads(req.text)
            version = data["info"]["version"]
            last_version._cache = (time.time(), version, True)
            return version
        except (
            KeyError,
            ValueError,
            requests.exceptions.RequestException
        ) as error:  # pragma: no cover (should not happen unless pypi is not available)
            logger.error(
                "Unable to fetch %s: %s" % (settings.CAS_NEW_VERSION_JSON_URL, error)
            )
            last_version._cache = (time.time(), version, False)


def dictfetchall(cursor):
    "Return all rows from a django cursor as a dict"
    columns = [col[0] for col in cursor.description]
    return [
        dict(zip(columns, row))
        for row in cursor.fetchall()
    ]


def logout_request(ticket):
    """
        Forge a SLO logout request

        :param unicode ticket: A ticket value
        :return: A SLO XML body request
        :rtype: unicode
    """
    return u"""<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
 ID="%(id)s" Version="2.0" IssueInstant="%(datetime)s">
<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:NameID>
<samlp:SessionIndex>%(ticket)s</samlp:SessionIndex>
</samlp:LogoutRequest>""" % {
        'id': gen_saml_id(),
        'datetime': timezone.now().isoformat(),
        'ticket':  ticket
    }


def regexpr_validator(value):
    """
        Test that ``value`` is a valid regular expression

        :param unicode value: A regular expression to test
        :raises ValidationError: if ``value`` is not a valid regular expression
    """
    try:
        re.compile(value)
    except re.error:
        raise ValidationError(
            _('"%(value)s" is not a valid regular expression'),
            params={'value': value}
        )
