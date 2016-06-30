CAS Server
==========

.. image:: https://travis-ci.org/nitmir/django-cas-server.svg?branch=master
    :target: https://travis-ci.org/nitmir/django-cas-server

.. image:: https://img.shields.io/pypi/v/django-cas-server.svg
    :target: https://pypi.python.org/pypi/django-cas-server

.. image:: https://img.shields.io/pypi/l/django-cas-server.svg
    :target: https://www.gnu.org/licenses/gpl-3.0.html

.. image:: https://api.codacy.com/project/badge/Grade/255c21623d6946ef8802fa7995b61366
    :target: https://www.codacy.com/app/valentin-samir/django-cas-server

.. image:: https://api.codacy.com/project/badge/Coverage/255c21623d6946ef8802fa7995b61366
    :target: https://www.codacy.com/app/valentin-samir/django-cas-server

CAS Server is a Django application implementing the `CAS Protocol 3.0 Specification
<https://apereo.github.io/cas/4.2.x/protocol/CAS-Protocol-Specification.html>`_.

By defaut, the authentication process use django internal users but you can easily
use any sources (see auth classes in the auth.py file)

The defaut login/logout template use `django-bootstrap3 <https://github.com/dyve/django-bootstrap3>`_
but you can use your own templates using settings variables.

Note that for Django 1.7 compatibility, you need a version of
`django-bootstrap3 <https://github.com/dyve/django-bootstrap3>`_ < 7.0.0
like the 6.2.2 version.

Features
--------

* Support CAS version 1.0, 2.0, 3.0
* Support Single Sign Out
* Configuration of services via the django Admin application
* Fine control on which user's attributes are passed to which service
* Possibility to rename/rewrite attributes per service
* Possibility to require some attribute values per service
* Supports Django 1.7, 1.8 and 1.9
* Supports Python 2.7, 3.x

Quick start
-----------
0. If you want to make a virtualenv for ``django-cas-server``, you will need the following
   dependencies on a bare debian like system::

    virtualenv build-essential python-dev libxml2-dev libxslt1-dev zlib1g-dev

   If you want to use python3 instead of python2, replace ``python-dev`` with ``python3-dev``.

   If you intend to run the tox tests you will also need ``python3.4-dev`` depending of the current
   version of python3 on your system.

1. Add "cas_server" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = (
        'django.contrib.admin',
        ...
        'bootstrap3',
        'cas_server',
    )

   For internatinalization support, add "django.middleware.locale.LocaleMiddleware"
   to your MIDDLEWARE_CLASSES setting like this::

    MIDDLEWARE_CLASSES = (
        ...
        'django.middleware.locale.LocaleMiddleware',
        ...
    )

2. Include the cas_server URLconf in your project urls.py like this::

    urlpatterns = [
        url(r'^admin/', admin.site.urls),
        ...
        url(r'^cas/', include('cas_server.urls', namespace="cas_server")),
    ]

3. Run `python manage.py migrate` to create the cas_server models.


4. You should add some management commands to a crontab: ``clearsessions``,
   ``cas_clean_tickets`` and ``cas_clean_sessions``.

 * ``clearsessions``:  please see `Clearing the session store <https://docs.djangoproject.com/en/stable/topics/http/sessions/#clearing-the-session-store>`_.
 * ``cas_clean_tickets``: old tickets and timed-out tickets do not get purge from
   the database automatically. They are just marked as invalid. ``cas_clean_tickets``
   is a clean-up management command for this purpose. It send SingleLogOut request
   to services with timed out tickets and delete them.
 * ``cas_clean_sessions``: Logout and purge users (sending SLO requests) that are
   inactive since more than ``SESSION_COOKIE_AGE``. The default value for is ``1209600``
   seconds (2 weeks). You probably should reduce it to something like ``86400`` seconds (1 day).

 You could for example do as bellow :

   .. code-block::

      0   0  * * * cas-user /path/to/project/manage.py clearsessions
      */5 *  * * * cas-user /path/to/project/manage.py cas_clean_tickets
      5   0  * * * cas-user /path/to/project/manage.py cas_clean_sessions

5. Start the development server and visit http://127.0.0.1:8000/admin/
   to add a first service allowed to authenticate user agains the CAS
   (you'll need the Admin app enabled).

6. Visit http://127.0.0.1:8000/cas/ to login with your django users.




Settings
--------

All settings are optional. Add them to ``settings.py`` to customize ``django-cas-server``:


Template settings:

* ``CAS_LOGO_URL``: Url to the logo showed in the up left corner on the default
  templates. Set it to ``False`` to disable it.

* ``CAS_LOGIN_TEMPLATE``: Path to the template showed on ``/login`` then the user
  is not autenticated.  The default is ``"cas_server/login.html"``.
* ``CAS_WARN_TEMPLATE``: Path to the template showed on ``/login?service=...`` then
  the user is authenticated and has asked to be warned before beeing connected
  to a service. The default is ``"cas_server/warn.html"``.
* ``CAS_LOGGED_TEMPLATE``: Path to the template showed on ``/login`` then to user is
  authenticated. The default is ``"cas_server/logged.html"``.
* ``CAS_LOGOUT_TEMPLATE``: Path to the template showed on ``/logout`` then to user
  is being disconnected. The default is ``"cas_server/logout.html"``
* ``CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT``: Should we redirect users to `/login` after they
  logged out instead of displaying ``CAS_LOGOUT_TEMPLATE``. The default is ``False``.


Authentication settings:

*  ``CAS_AUTH_CLASS``: A dotted path to a class or a class implementing
  ``cas_server.auth.AuthUser``. The default is ``"cas_server.auth.DjangoAuthUser"``

*  ``SESSION_COOKIE_AGE``: This is a django settings. Here, it control the delay in seconds after
   which inactive users are logged out. The default is ``1209600`` (2 weeks). You probably should
   reduce it to something like ``86400`` seconds (1 day).

* ``CAS_PROXY_CA_CERTIFICATE_PATH``: Path to certificate authorities file. Usually on linux
  the local CAs are in ``/etc/ssl/certs/ca-certificates.crt``. The default is ``True`` which
  tell requests to use its internal certificat authorities. Settings it to ``False`` should
  disable all x509 certificates validation and MUST not be done in production.
  x509 certificate validation is perform upon PGT issuance.

* ``CAS_SLO_MAX_PARALLEL_REQUESTS``: Maximum number of parallel single log out requests send.
  If more requests need to be send, there are queued. The default is ``10``.
* ``CAS_SLO_TIMEOUT``: Timeout for a single SLO request in seconds. The default is ``5``.

Tickets validity settings:

* ``CAS_TICKET_VALIDITY``: Number of seconds the service tickets and proxy tickets are valid.
  This is the maximal time between ticket issuance by the CAS and ticket validation by an
  application. The default is ``60``.
* ``CAS_PGT_VALIDITY``: Number of seconds the proxy granting tickets are valid.
  The default is ``3600`` (1 hour).
* ``CAS_TICKET_TIMEOUT``: Number of seconds a ticket is kept in the database before sending
  Single Log Out request and being cleared. The default is ``86400`` (24 hours).

Tickets miscellaneous settings:

* ``CAS_TICKET_LEN``: Default ticket length. All CAS implementation MUST support ST and PT
  up to 32 chars, PGT and PGTIOU up to 64 chars and it is RECOMMENDED that all tickets up
  to 256 chars are supports. Here the default is ``64``.
* ``CAS_LT_LEN``: Length of the login tickets. Login tickets are only processed by ``django-cas-server``
  thus there is no length restriction on it. The default is ``CAS_TICKET_LEN``.
* ``CAS_ST_LEN``: Length of the service tickets. The default is ``CAS_TICKET_LEN``.
  You may need to lower is to ``32`` if you use some old clients.
* ``CAS_PT_LEN``: Length of the proxy tickets. The default is ``CAS_TICKET_LEN``.
  This length should be the same as ``CAS_ST_LEN``. You may need to lower is to ``32``
  if you use some old clients.
* ``CAS_PGT_LEN``: Length of the proxy granting tickets. The default is ``CAS_TICKET_LEN``.
* ``CAS_PGTIOU_LEN``: Length of the proxy granting tickets IOU. The default is ``CAS_TICKET_LEN``.

* ``CAS_LOGIN_TICKET_PREFIX``: Prefix of login tickets. The default is ``"LT"``.
* ``CAS_SERVICE_TICKET_PREFIX``: Prefix of service tickets. The default is ``"ST"``.
  The CAS specification mandate that service tickets MUST begin with the characters ST
  so you should not change this.
* ``CAS_PROXY_TICKET_PREFIX``: Prefix of proxy ticket. The default is ``"PT"``.
* ``CAS_PROXY_GRANTING_TICKET_PREFIX``: Prefix of proxy granting ticket. The default is ``"PGT"``.
* ``CAS_PROXY_GRANTING_TICKET_IOU_PREFIX``: Prefix of proxy granting ticket IOU. The default is ``"PGTIOU"``.


Mysql backend settings. Only usefull if you are using the mysql authentication backend:

* ``CAS_SQL_HOST``: Host for the SQL server. The default is ``"localhost"``.
* ``CAS_SQL_USERNAME``: Username for connecting to the SQL server.
* ``CAS_SQL_PASSWORD``: Password for connecting to the SQL server.
* ``CAS_SQL_DBNAME``: Database name.
* ``CAS_SQL_DBCHARSET``: Database charset. The default is ``"utf8"``
* ``CAS_SQL_USER_QUERY``: The query performed upon user authentication.
  The username must be in field ``username``, the password in ``password``,
  additional fields are used as the user attributes.
  The default is ``"SELECT user AS usersame, pass AS password, users.* FROM users WHERE user = %s"``
* ``CAS_SQL_PASSWORD_CHECK``: The method used to check the user password. Must be one of the following:

    * ``"crypt"`` (see <https://en.wikipedia.org/wiki/Crypt_(C)>), the password in the database
      should begin this $
    * ``"ldap"`` (see https://tools.ietf.org/id/draft-stroeder-hashed-userpassword-values-01.html)
      the password in the database must begin with one of {MD5}, {SMD5}, {SHA}, {SSHA}, {SHA256},
      {SSHA256}, {SHA384}, {SSHA384}, {SHA512}, {SSHA512}, {CRYPT}.
    * ``"hex_HASH_NAME"`` with ``HASH_NAME`` in md5, sha1, sha224, sha256, sha384, sha512.
      The hashed password in the database is compare to the hexadecimal digest of the clear
      password hashed with the corresponding algorithm.
    * ``"plain"``, the password in the database must be in clear.

  The default is ``"crypt"``.


Test backend settings. Only usefull if you are using the test authentication backend:

* ``CAS_TEST_USER``: Username of the test user. The default is ``"test"``.
* ``CAS_TEST_PASSWORD``: Password of the test user. The default is ``"test"``.
* ``CAS_TEST_ATTRIBUTES``: Attributes of the test user. The default is
  ``{'nom': 'Nymous', 'prenom': 'Ano', 'email': 'anonymous@example.net',
  'alias': ['demo1', 'demo2']}``.


Authentication backend
----------------------

``django-cas-server`` comes with some authentication backends:

* dummy backend ``cas_server.auth.DummyAuthUser``: all authentication attempt fails.
* test backend ``cas_server.auth.TestAuthUser``: username, password and returned attributes
  for the user are defined by the ``CAS_TEST_*`` settings.
* django backend ``cas_server.auth.DjangoAuthUser``: Users are authenticated agains django users system.
  This is the default backend. The returned attributes are the fields available on the user model.
* mysql backend ``cas_server.auth.MysqlAuthUser``: see the 'Mysql backend settings' section.
  The returned attributes are those return by sql query ``CAS_SQL_USER_QUERY``.

Logs
----

``django-cas-server`` logs most of its actions. To enable login, you must set the ``LOGGING``
(https://docs.djangoproject.com/en/stable/topics/logging) variable in ``settings.py``.

Users successful actions (login, logout) are logged with the level ``INFO``, failures are logged
with the level ``WARNING`` and user attributes transmitted to a service are logged with the level ``DEBUG``.

For exemple to log to syslog you can use :

.. code-block:: python

    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'cas_syslog': {
                'format': 'cas: %(levelname)s %(message)s'
            },
        },
        'handlers': {
            'cas_syslog': {
                'level': 'INFO',
                'class': 'logging.handlers.SysLogHandler',
                'address': '/dev/log',
                'formatter': 'cas_syslog',
            },
        },
        'loggers': {
            'cas_server': {
                'handlers': ['cas_syslog'],
                'level': 'INFO',
                'propagate': True,
            },
        },
    }


Or to log to a file:

.. code-block:: python

    LOGGING = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'cas_file': {
                'format': '%(asctime)s %(levelname)s %(message)s'
            },
        },
        'handlers': {
            'cas_file': {
                'level': 'INFO',
                'class': 'logging.FileHandler',
                'filename': '/tmp/cas_server.log',
                'formatter': 'cas_file',
            },
        },
        'loggers': {
            'cas_server': {
                'handlers': ['cas_file'],
                'level': 'INFO',
                'propagate': True,
            },
        },
    }
