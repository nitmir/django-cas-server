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
"""Default values for the app's settings"""
from django.conf import settings
from django.templatetags.static import static

from importlib import import_module

import sys
if sys.version_info < (3, ):
    from django.utils.translation import ugettext_lazy as _
else:
    from django.utils.translation import gettext_lazy as _


try:
    #: URL to the logo showed in the up left corner on the default templates.
    CAS_LOGO_URL = static("cas_server/logo.png")
    #: URL to the favicon (shortcut icon) used by the default templates. Default is a key icon.
    CAS_FAVICON_URL = static("cas_server/favicon.ico")
# is settings.DEBUG is False and collectstatics has not been run yet, the static function will
# raise a ValueError because the file is not found.
except ValueError:
    #: URL to the logo showed in the up left corner on the default templates.
    CAS_LOGO_URL = None
    #: URL to the favicon (shortcut icon) used by the default templates. Default is a key icon.
    CAS_FAVICON_URL = None


#: Show the powered by footer if set to ``True``
CAS_SHOW_POWERED = True
#: URLs to css and javascript external components.
CAS_COMPONENT_URLS = {
    "bootstrap3_css": "//maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css",
    "bootstrap3_js": "//maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js",
    "html5shiv": "//oss.maxcdn.com/libs/html5shiv/3.7.0/html5shiv.js",
    "respond": "//oss.maxcdn.com/libs/respond.js/1.4.2/respond.min.js",
    "bootstrap4_css": "//stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css",
    "bootstrap4_js": "//stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js",
    "jquery": "//code.jquery.com/jquery.min.js",
}
#: Path to the template showed on /login then the user is not autenticated.
CAS_LOGIN_TEMPLATE = 'cas_server/bs4/login.html'
#: Path to the template showed on /login?service=... then the user is authenticated and has asked
#: to be warned before being connected to a service.
CAS_WARN_TEMPLATE = 'cas_server/bs4/warn.html'
#: Path to the template showed on /login then to user is authenticated.
CAS_LOGGED_TEMPLATE = 'cas_server/bs4/logged.html'
#: Path to the template showed on /logout then to user is being disconnected.
CAS_LOGOUT_TEMPLATE = 'cas_server/bs4/logout.html'
#: Should we redirect users to /login after they logged out instead of displaying
#: :obj:`CAS_LOGOUT_TEMPLATE`.
CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT = False


#: A dotted path to a class or a class implementing cas_server.auth.AuthUser.
CAS_AUTH_CLASS = 'cas_server.auth.DjangoAuthUser'
#: Path to certificate authorities file. Usually on linux the local CAs are in
#: /etc/ssl/certs/ca-certificates.crt. ``True`` tell requests to use its internal certificat
#: authorities.
CAS_PROXY_CA_CERTIFICATE_PATH = True
#: Maximum number of parallel single log out requests send
#: if more requests need to be send, there are queued
CAS_SLO_MAX_PARALLEL_REQUESTS = 10
#: Timeout for a single SLO request in seconds.
CAS_SLO_TIMEOUT = 5
#: Shared to transmit then using the view :class:`cas_server.views.Auth`
CAS_AUTH_SHARED_SECRET = ''
#: Max time after with the user MUST reauthenticate. Let it to `None` for no max time.
#: This can be used to force refreshing cached informations only available upon user authentication
#: like the user attributes in federation mode or with the ldap auth in bind mode.
CAS_TGT_VALIDITY = None


#: Number of seconds the service tickets and proxy tickets are valid. This is the maximal time
#: between ticket issuance by the CAS and ticket validation by an application.
CAS_TICKET_VALIDITY = 60
#: Number of seconds the proxy granting tickets are valid.
CAS_PGT_VALIDITY = 3600
#: Number of seconds a ticket is kept in the database before sending Single Log Out request and
#: being cleared.
CAS_TICKET_TIMEOUT = 24*3600


#: All CAS implementation MUST support ST and PT up to 32 chars,
#: PGT and PGTIOU up to 64 chars and it is RECOMMENDED that all
#: tickets up to 256 chars are supports so we use 64 for the default
#: len.
CAS_TICKET_LEN = 64

#: alias of :obj:`settings.CAS_TICKET_LEN`
CAS_LT_LEN = getattr(settings, 'CAS_TICKET_LEN', CAS_TICKET_LEN)
#: alias of :obj:`settings.CAS_TICKET_LEN`
#: Services MUST be able to accept service tickets of up to 32 characters in length.
CAS_ST_LEN = getattr(settings, 'CAS_TICKET_LEN', CAS_TICKET_LEN)
#: alias of :obj:`settings.CAS_TICKET_LEN`
#: Back-end services MUST be able to accept proxy tickets of up to 32 characters.
CAS_PT_LEN = getattr(settings, 'CAS_TICKET_LEN', CAS_TICKET_LEN)
#: alias of :obj:`settings.CAS_TICKET_LEN`
#: Services MUST be able to handle proxy-granting tickets of up to 64
CAS_PGT_LEN = getattr(settings, 'CAS_TICKET_LEN', CAS_TICKET_LEN)
#: alias of :obj:`settings.CAS_TICKET_LEN`
#: Services MUST be able to handle PGTIOUs of up to 64 characters in length.
CAS_PGTIOU_LEN = getattr(settings, 'CAS_TICKET_LEN', CAS_TICKET_LEN)

#: Prefix of login tickets.
CAS_LOGIN_TICKET_PREFIX = u'LT'
#: Prefix of service tickets. Service tickets MUST begin with the characters ST so you should not
#: change this.
CAS_SERVICE_TICKET_PREFIX = u'ST'
#: Prefix of proxy ticket. Proxy tickets SHOULD begin with the characters, PT.
CAS_PROXY_TICKET_PREFIX = u'PT'
#: Prefix of proxy granting ticket. Proxy-granting tickets SHOULD begin with the characters PGT.
CAS_PROXY_GRANTING_TICKET_PREFIX = u'PGT'
#: Prefix of proxy granting ticket IOU. Proxy-granting ticket IOUs SHOULD begin with the characters
#: PGTIOU.
CAS_PROXY_GRANTING_TICKET_IOU_PREFIX = u'PGTIOU'


#: Host for the SQL server.
CAS_SQL_HOST = 'localhost'
#: Username for connecting to the SQL server.
CAS_SQL_USERNAME = ''
#: Password for connecting to the SQL server.
CAS_SQL_PASSWORD = ''
#: Database name.
CAS_SQL_DBNAME = ''
#: Database charset.
CAS_SQL_DBCHARSET = 'utf8'

#: The query performed upon user authentication.
CAS_SQL_USER_QUERY = 'SELECT user AS username, pass AS password, users.* FROM users WHERE user = %s'
#: The method used to check the user password. Must be one of ``"crypt"``, ``"ldap"``,
#: ``"hex_md5"``, ``"hex_sha1"``, ``"hex_sha224"``, ``"hex_sha256"``, ``"hex_sha384"``,
#: ``"hex_sha512"``, ``"plain"``.
CAS_SQL_PASSWORD_CHECK = 'crypt'
#: charset the SQL users passwords was hash with
CAS_SQL_PASSWORD_CHARSET = "utf-8"


#: Address of the LDAP server
CAS_LDAP_SERVER = 'localhost'
#: LDAP user bind address, for example ``"cn=admin,dc=crans,dc=org"`` for connecting to the LDAP
#: server.
CAS_LDAP_USER = None
#: LDAP connection password
CAS_LDAP_PASSWORD = None
#: LDAP seach base DN, for example ``"ou=data,dc=crans,dc=org"``.
CAS_LDAP_BASE_DN = None
#: LDAP search filter for searching user by username. User inputed usernames are escaped using
#: :func:`ldap3.utils.conv.escape_bytes`.
CAS_LDAP_USER_QUERY = "(uid=%s)"
#: LDAP attribute used for users usernames
CAS_LDAP_USERNAME_ATTR = "uid"
#: LDAP attribute used for users passwords
CAS_LDAP_PASSWORD_ATTR = "userPassword"
#: The method used to check the user password. Must be one of ``"crypt"``, ``"ldap"``,
#: ``"hex_md5"``, ``"hex_sha1"``, ``"hex_sha224"``, ``"hex_sha256"``, ``"hex_sha384"``,
#: ``"hex_sha512"``, ``"plain"``, ``"bind"``.
CAS_LDAP_PASSWORD_CHECK = "ldap"
#: charset the LDAP users passwords was hash with
CAS_LDAP_PASSWORD_CHARSET = "utf-8"
#: This parameter is only used then ``CAS_LDAP_PASSWORD_CHECK`` is set to ``"bind"``.
#:
#:  * if ``0`` the user attributes are retrieved by connecting to the ldap as ``CAS_LDAP_USER``.
#:  * if ``1`` the user attributes are retrieve then the user authenticate using
#:    the user credentials. These attributes are then cached for the session.
#:
#: The default is ``0``.
CAS_LDAP_ATTRS_VIEW = 0


#: Username of the test user.
CAS_TEST_USER = 'test'
#: Password of the test user.
CAS_TEST_PASSWORD = 'test'
#: Attributes of the test user.
CAS_TEST_ATTRIBUTES = {
    'nom': 'Nymous',
    'prenom': 'Ano',
    'email': 'anonymous@example.net',
    'alias': ['demo1', 'demo2']
}


#: A :class:`bool` for activatinc the hability to fetch tickets using javascript.
CAS_ENABLE_AJAX_AUTH = False


#: A :class:`bool` for activating the federated mode
CAS_FEDERATE = False
#: Time after witch the cookie use for “remember my identity provider” expire (one week).
CAS_FEDERATE_REMEMBER_TIMEOUT = 604800

#: A :class:`bool` for diplaying a warning on html pages then a new version of the application
#: is avaible. Once closed by a user, it is not displayed to this user until the next new version.
CAS_NEW_VERSION_HTML_WARNING = True
#: A :class:`bool` for sending emails to ``settings.ADMINS`` when a new version is available.
CAS_NEW_VERSION_EMAIL_WARNING = True
#: URL to the pypi json of the application. Used to retreive the version number of the last version.
#: You should not change it.
CAS_NEW_VERSION_JSON_URL = "https://pypi.org/pypi/django-cas-server/json"

#: If the service message should be displayed on the login page
CAS_SHOW_SERVICE_MESSAGES = True

#: Messages displayed in a info-box on the html pages of the default templates.
#: ``CAS_INFO_MESSAGES`` is a :class:`dict` mapping message name to a message :class:`dict`.
#: A message :class:`dict` has 3 keys:
#:
#: * ``message``: A :class:`unicode`, the message to display, potentially wrapped around
#:   ugettex_lazy
#: * ``discardable``: A :class:`bool`, specify if the users can close the message info-box
#: * ``type``: One of info, success, info, warning, danger. The type of the info-box.
#:
#: ``CAS_INFO_MESSAGES`` contains by default one message, ``cas_explained``, which explain
#: roughly the purpose of a CAS.
CAS_INFO_MESSAGES = {
    "cas_explained": {
        "message": _(
            u"The Central Authentication Service grants you access to most of our websites by "
            u"authenticating only once, so you don't need to type your credentials again unless "
            u"your session expires or you logout."
        ),
        "discardable": True,
        "type": "info",  # one of info, success, info, warning, danger
    },
}
#: :class:`list` of message names. Order in which info-box messages are displayed.
#: Let the list empty to disable messages display.
CAS_INFO_MESSAGES_ORDER = []

#: :class:`bool` If `True` Django session cookie will be removed on logout from CAS server
CAS_REMOVE_DJANGO_SESSION_COOKIE_ON_LOGOUT = False
#: :class:`bool` If `True` Django csrf cookie will be removed on logout from CAS server
CAS_REMOVE_DJANGO_CSRF_COOKIE_ON_LOGOUT = False
#: :class:`bool` If `True` Django language cookie will be removed on logout from CAS server
CAS_REMOVE_DJANGO_LANGUAGE_COOKIE_ON_LOGOUT = False


GLOBALS = globals().copy()
for name, default_value in GLOBALS.items():
    # only care about parameter begining by CAS_
    if name.startswith("CAS_"):
        # get the current setting value, falling back to default_value
        value = getattr(settings, name, default_value)
        # set the setting value to its value if defined, ellse to the default_value.
        setattr(settings, name, value)

# Allow the user defined CAS_COMPONENT_URLS to omit not changed values
MERGED_CAS_COMPONENT_URLS = CAS_COMPONENT_URLS.copy()
MERGED_CAS_COMPONENT_URLS.update(settings.CAS_COMPONENT_URLS)
settings.CAS_COMPONENT_URLS = MERGED_CAS_COMPONENT_URLS

# if the federated mode is enabled, we must use the :class`cas_server.auth.CASFederateAuth` auth
# backend.
if settings.CAS_FEDERATE:
    settings.CAS_AUTH_CLASS = "cas_server.auth.CASFederateAuth"


#: SessionStore class depending of :django:setting:`SESSION_ENGINE`
SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
