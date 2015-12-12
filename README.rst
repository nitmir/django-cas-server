CAS Server
==========

.. image:: https://badge.fury.io/py/django-cas-server.svg
    :target: https://badge.fury.io/py/django-cas-server

.. image:: https://travis-ci.org/nitmir/django-cas-server.svg?branch=master
    :target: https://travis-ci.org/nitmir/django-cas-server

CAS Server is a Django app implementing the `CAS Protocol 3.0 Specification
<https://jasig.github.io/cas/development/protocol/CAS-Protocol-Specification.html>`_.

By defaut, the authentication process use django internal users but you can easily
use any sources (see auth classes in the auth.py file)

The differents parametters you can use in settings.py to tweak the application
are listed in default_settings.py

The defaut login/logout template use `django-bootstrap3 <https://github.com/dyve/django-bootstrap3>`_
but you can use your own templates using the CAS_LOGIN_TEMPLATE,
CAS_LOGGED_TEMPLATE, CAS_WARN_TEMPLATE and CAS_LOGOUT_TEMPLATE setting variables.

Quick start
-----------

1. Add "cas_server" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = (
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

2. Include the polls URLconf in your project urls.py like this::

    url(r'^cas/', include('cas_server.urls', namespace="cas_server")),

3. Run `python manage.py migrate` to create the cas_server models.

4. Start the development server and visit http://127.0.0.1:8000/admin/
   to add a first service allowed to authenticate user agains the CAS
   (you'll need the Admin app enabled).

5. Visit http://127.0.0.1:8000/cas/ to login with your django users.

Settings
--------

All settings are optional. Add them to ``settings.py`` to customize ``django-cas-server``:


Template settings:

* ``CAS_LOGIN_TEMPLATE``: Path to the template showed on ``/login`` then the user
  is not autenticated.  The default is ``"cas_server/login.html"``.
* ``CAS_WARN_TEMPLATE``: Path to the template showed on ``/login?service=…`` then
  the user is authenticated and has asked to be warned before beeing connected
  to a service. The default is ``"cas_server/warn.html"``.
* ``CAS_LOGGED_TEMPLATE``: Path to the template showed on ``/login`` then to user is
  authenticated. The default is ``"cas_server/logged.html"``.
* ``CAS_LOGOUT_TEMPLATE``: Path to the template showed on ``/logout`` then to user
  is being disconnected. The default is ``"cas_server/logout.html"``
* ``CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT``: Should we redirect users to `/login` after they
  logged out instead of displaying ``CAS_LOGOUT_TEMPLATE``. The default is ``False``.


Authentication settings:

*  ``CAS_AUTH_CLASS``: A dotted paths to a class implementing ``cas_server.auth.AuthUser``.
   The default is ``"cas_server.auth.DjangoAuthUser"``

* ``CAS_PROXY_CA_CERTIFICATE_PATH``: Path to certificates authority file. Usually on linux
  the local CAs are in ``/etc/ssl/certs/ca-certificates.crt``. The default is ``True`` which
  tell requests to use its internal certificat authorities. Settings it to ``False`` should
  disable all x509 certificates validation and MUST not be done in production.
  x509 certificate validation is perform upon PGT issuance.

* ``CAS_SLO_MAX_PARALLEL_REQUESTS``: Maximum number of parallel single log out requests send.
  If more requests need to be send, there are queued. The default is ``10``.

Tickets validity settings:

* ``CAS_TICKET_VALIDITY``: Number of seconds the service tickets and proxy tickets are valid.
  This is the maximal time between ticket issuance by the CAS and ticket validation by an
  application. The default is ``60``.
* ``CAS_PGT_VALIDITY``: Number of seconds the proxy granting tickets are valid.
  The default is ``3600`` (1 hour).
* ``CAS_TICKET_TIMEOUT``: Number of seconds a ticket is kept is the database before sending
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
* ``CAS_PROXY_TICKET_PREFIX``: Prefix of proxy ticket. The default is ``"ST"``.
* ``CAS_PROXY_GRANTING_TICKET_PREFIX``: Prefix of proxy granting ticket. The default is ``"PGT"``.
* ``CAS_PROXY_GRANTING_TICKET_IOU_PREFIX``: Prefix of proxy granting ticket IOU. The default is ``"PGTIOU"``.


Mysql backend settings. Only usefull is you use the mysql authentication backend:

* ``CAS_SQL_HOST``: Host for the SQL server. The default is ``"localhost"``.
* ``CAS_SQL_USERNAME``: Username for connecting to the SQL server.
* ``CAS_SQL_PASSWORD``: Password for connecting to the SQL server.
* ``CAS_SQL_DBNAME``: Database name.
* ``CAS_SQL_DBCHARSET``: Database charset. The default is ``"utf8"``
* ``CAS_SQL_USER_QUERY``: The query performed upon user authentication.
  The username must be in field ``username``, the password in ``password``,
  additional fields are used as the user attributs.
  The default is ``"SELECT user AS usersame, pass AS password, users.* FROM users WHERE user = %s"``
* ``CAS_SQL_PASSWORD_CHECK``: The method used to check the user password. Must be
  ``"crypt"`` or ``"plain``". The default is ``"crypt"``.

Authentication backend
----------------------

``django-cas-server`` comes with some authentication backends:

* dummy backend ``cas_server.auth.DummyAuthUser``: all authentication attempt fails.
* test backend ``cas_server.auth.TestAuthUser``: username is ``test`` and password is ``test``
  the returned attributs for the user are: ``{'nom': 'Nymous', 'prenom': 'Ano', 'email': 'anonymous@example.net'}``
* django backend ``cas_server.auth.DjangoAuthUser``: Users are anthenticated agains django users system.
  This is the default backend. The returned attributs are the fields available on the user model.
* mysql backend ``cas_server.auth.MysqlAuthUser``: see the 'Mysql backend settings' section.
  The returned attributs are those return by sql query ``CAS_SQL_USER_QUERY``.
