CAS Server
##########

|travis| |coverage| |licence| |github_version| |pypi_version| |codacy| |doc|

CAS Server is a Django application implementing the `CAS Protocol 3.0 Specification
<https://apereo.github.io/cas/4.2.x/protocol/CAS-Protocol-Specification.html>`_.

By default, the authentication process uses django internal users but you can easily
use any source (see the `Authentication backend`_ section and auth classes in the auth.py file)

.. contents:: Table of Contents

Features
========

* Support CAS version 1.0, 2.0, 3.0
* Support Single Sign Out
* Configuration of services via the Django Admin application
* Fine control on which user's attributes are passed to which service
* Possibility to rename/rewrite attributes per service
* Possibility to require some attribute values per service
* Federated mode between multiple CAS
* Supports Django 1.11, 2.2, 3.2, 4.0 and 4.1
* Supports Python 3.6+

Dependencies
============

``django-cas-server`` depends on the following python packages:

* Django >= 1.11 < 4.2
* requests >= 2.4
* requests_futures >= 0.9.5
* lxml >= 3.4
* six >= 1.8

Minimal version of package dependencies are just indicative and means that ``django-cas-server`` has
been tested with it. Previous versions of dependencies may or may not work.

Additionally, depending on the `Authentication backend`_ you plan to use, you may need the following
python packages:

* ldap3
* psycopg2
* mysql-python


Here is a table with the name of python packages and the corresponding packages providing
them on debian like systems and centos like systems.
You should try as much as possible to use system packages as they are automatically updated when
you update your system. You can then install Not Available (N/A)
packages on your system using pip3 inside a virtualenv as described in the `Installation`_ section.
For use with python2, just replace python3(6) in the table by python.

+------------------+--------------------------+---------------------+
| python package   | debian like systems      | centos like systems |
+==================+==========================+=====================+
| Django           | python3-django           | python36-django     |
+------------------+--------------------------+---------------------+
| requests         | python3-requests         | python36-requests   |
+------------------+--------------------------+---------------------+
| requests_futures | python3-requests-futures | N/A                 |
+------------------+--------------------------+---------------------+
| lxml             | python3-lxml             | python36-lxml       |
+------------------+--------------------------+---------------------+
| six              | python3-six              | python36-six        |
+------------------+--------------------------+---------------------+
| ldap3            | python3-ldap3            | python36-ldap3      |
+------------------+--------------------------+---------------------+
| psycopg2         | python3-psycopg2         | python36-psycopg2   |
+------------------+--------------------------+---------------------+
| mysql-python     | python3-mysqldb          | python36-mysql      |
+------------------+--------------------------+---------------------+

Installation
============

The recommended installation mode is to use a virtualenv with ``--system-site-packages``

1. Make sure that python virtualenv is installed

2. Install python packages available via the system package manager:

   On debian like systems::

    $ sudo apt-get install python3-django python3-requests python3-six python3-lxml python3-requests-futures

   On debian jessie, you can use the version of python-django available in the
   `backports <https://backports.debian.org/Instructions/>`_.

   On centos like systems with epel enabled::

    $ sudo yum install python36-django python36-requests python36-six python36-lxml

3. Create a virtualenv::

    $ virtualenv -p python3 --system-site-packages cas_venv

4. And `activate it <https://virtualenv.pypa.io/en/stable/userguide/#activate-script>`__::

    $ cd cas_venv/; . bin/activate

5. Create a django project::

   $ django-admin startproject cas_project
   $ cd cas_project

6. Install `django-cas-server`. To use the last published release, run::

    $ pip install django-cas-server

   Alternatively if you want to use the version of the git repository, you can clone it::

    $ git clone https://github.com/nitmir/django-cas-server
    $ cd django-cas-server
    $ pip install -r requirements.txt

   Then, either run ``make install`` to create a python package using the sources of the repository
   and install it with pip, or place the ``cas_server`` directory into your
   `PYTHONPATH <https://docs.python.org/2/using/cmdline.html#envvar-PYTHONPATH>`_
   (for instance by symlinking ``cas_server`` to the root of your django project).

7. Open ``cas_project/settings.py`` in your favourite editor and follow the quick start section.


Quick start
===========

1. Add "cas_server" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = (
        'django.contrib.admin',
        ...
        'cas_server',
    )

   For internationalization support, add "django.middleware.locale.LocaleMiddleware"
   to your MIDDLEWARE setting like this::

    MIDDLEWARE = [
        ...
        'django.middleware.locale.LocaleMiddleware',
        ...
    ]

2. Include the cas_server URLconf in your project urls.py like this::

    from django.conf.urls import url, include

    urlpatterns = [
        url(r'^admin/', admin.site.urls),
        ...
        url(r'^cas/', include('cas_server.urls', namespace="cas_server")),
    ]

3. Run ``python manage.py migrate`` to create the cas_server models.


4. You should add some management commands to a crontab: ``clearsessions``,
   ``cas_clean_tickets`` and ``cas_clean_sessions``.

   * ``clearsessions``:  please see `Clearing the session store <https://docs.djangoproject.com/en/stable/topics/http/sessions/#clearing-the-session-store>`_.
   * ``cas_clean_tickets``: old tickets and timed-out tickets do not get purged from
     the database automatically. They are just marked as invalid. ``cas_clean_tickets``
     is a clean-up management command for this purpose. It sends SingleLogOut requests
     to services with timed out tickets and deletes them.
   * ``cas_clean_sessions``: Logout and purge users (sending SLO requests) that are
     inactive more than ``SESSION_COOKIE_AGE``. The default value is ``1209600``
     seconds (2 weeks). You probably should reduce it to something like ``86400`` seconds (1 day).

   You could, for example, do as below::

     0   0  * * * cas-user /path/to/project/manage.py clearsessions
     */5 *  * * * cas-user /path/to/project/manage.py cas_clean_tickets
     5   0  * * * cas-user /path/to/project/manage.py cas_clean_sessions

5. Run ``python manage.py createsuperuser`` to create an administrator user.

6. Start the development server and visit http://127.0.0.1:8000/admin/
   to add a first service allowed to authenticate user against the CAS
   (you'll need the Admin app enabled). See the `Service Patterns`_ section below.

7. Visit http://127.0.0.1:8000/cas/ to login with your django users.




Settings
========

All settings are optional. Add them to ``settings.py`` to customize ``django-cas-server``:


Template settings
-----------------

* ``CAS_LOGO_URL``: URL to the logo shown in the upper left corner on the default
  template. Set it to ``False`` to disable it.
* ``CAS_FAVICON_URL``: URL to the favicon (shortcut icon) used by the default templates.
  Default is a key icon. Set it to ``False`` to disable it.
* ``CAS_SHOW_POWERED``: Set it to ``False`` to hide the powered by footer. The default is ``True``.
* ``CAS_COMPONENT_URLS``: URLs to css and javascript external components. It is a dictionary
  having the five following keys: ``"bootstrap3_css"``, ``"bootstrap3_js"``,
  ``bootstrap4_css``, ``bootstrap4_js``, ``"html5shiv"``, ``"respond"``, ``"jquery"``.
  The default is::

        {
            "bootstrap3_css": "//maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css",
            "bootstrap3_js": "//maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js",
            "html5shiv": "//oss.maxcdn.com/libs/html5shiv/3.7.0/html5shiv.js",
            "respond": "//oss.maxcdn.com/libs/respond.js/1.4.2/respond.min.js",
            "bootstrap4_css": "//stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css",
            "bootstrap4_js": "//stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js",
            "jquery": "//code.jquery.com/jquery.min.js",
        }

  if you omit some keys of the dictionary, the default value for these keys is used.
* ``CAS_SHOW_SERVICE_MESSAGES``: Messages displayed about the state of the service on the login page.
  The default is ``True``.
* ``CAS_INFO_MESSAGES``: Messages displayed in info-boxes on the html pages of the default templates.
  It is a dictionary mapping message name to a message dict. A message dict has 3 keys:

  * ``message``: A unicode message to display, potentially wrapped around ugettex_lazy
  * ``discardable``: A boolean, specify if the users can close the message info-box
  * ``type``: One of info, success, warning, danger. The type of the info-box.

  ``CAS_INFO_MESSAGES`` contains by default one message, ``cas_explained``, which explains
  roughly the purpose of a CAS. The default is::

    {
        "cas_explained": {
            "message":_(
                u"The Central Authentication Service grants you access to most of our websites by "
                u"authenticating only once, so you don't need to type your credentials again unless "
                u"your session expires or you logout."
            ),
            "discardable": True,
            "type": "info",  # one of info, success, warning, danger
        },
    }

* ``CAS_INFO_MESSAGES_ORDER``: A list of message names. Order in which info-box messages are
  displayed. Use an empty list to disable messages display. The default is ``[]``.
* ``CAS_LOGIN_TEMPLATE``: Path to the template shown on ``/login`` when the user
  is not autenticated.  The default is ``"cas_server/bs4/login.html"``.
* ``CAS_WARN_TEMPLATE``: Path to the template shown on ``/login?service=...`` when
  the user is authenticated and has asked to be warned before being connected
  to a service. The default is ``"cas_server/bs4/warn.html"``.
* ``CAS_LOGGED_TEMPLATE``: Path to the template shown on ``/login`` when the user is
  authenticated. The default is ``"cas_server/bs4/logged.html"``.
* ``CAS_LOGOUT_TEMPLATE``: Path to the template shown on ``/logout`` when the user
  is being disconnected. The default is ``"cas_server/bs4/logout.html"``
* ``CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT``: Should we redirect users to ``/login`` after they
  logged out instead of displaying ``CAS_LOGOUT_TEMPLATE``. The default is ``False``.

Note that the old bootstrap3 template is available in ``cas_server/bs3/``


Authentication settings
-----------------------

* ``CAS_AUTH_CLASS``: A dotted path to a class or a class implementing
  ``cas_server.auth.AuthUser``. The default is ``"cas_server.auth.DjangoAuthUser"``
  Available classes bundled with ``django-cas-server`` are listed below in the
  `Authentication backend`_ section.

* ``SESSION_COOKIE_AGE``: This is a django setting. Here, it controls the delay in seconds after
  which inactive users are logged out. The default is ``1209600`` (2 weeks). You probably should
  reduce it to something like ``86400`` seconds (1 day).

* ``CAS_TGT_VALIDITY``: Max time after which the user MUST reauthenticate. Set it to `None` for no
  max time. This can be used to force refreshing cached information only available upon user
  authentication like the user attributes in federation mode or with the ldap auth in bind mode.
  The default is ``None``.

* ``CAS_PROXY_CA_CERTIFICATE_PATH``: Path to certificate authorities file. Usually on linux
  the local CAs are in ``/etc/ssl/certs/ca-certificates.crt``. The default is ``True`` which
  tells requests to use its internal certificate authorities. Setting it to ``False`` should
  disable all x509 certificate validation and MUST not be done in production.
  x509 certificate validation is performed upon PGT issuance.

* ``CAS_SLO_MAX_PARALLEL_REQUESTS``: Maximum number of parallel single log out requests sent.
  If more requests need to be sent, they are queued. The default is ``10``.
  
* ``CAS_SLO_TIMEOUT``: Timeout for a single SLO request in seconds. The default is ``5``.

* ``CAS_REMOVE_DJANGO_SESSION_COOKIE_ON_LOGOUT``: If `True` Django session cookie will be removed
  on logout from CAS server (default `False`). Note that Django session middleware will generate
  a new session cookie.

* ``CAS_REMOVE_DJANGO_CSRF_COOKIE_ON_LOGOUT``: If `True` Django csrf cookie will be removed on
  logout from CAS server (default `False`). Note that Django csrf middleware will generate a new
  csrf token cookie.

* ``CAS_REMOVE_DJANGO_LANGUAGE_COOKIE_ON_LOGOUT``: If `True` Django language cookie will be
  removed on logout from CAS server (default `False`).


Federation settings
-------------------

* ``CAS_FEDERATE``: A boolean for activating the federated mode (see the `Federation mode`_
  section below). The default is ``False``.
* ``CAS_FEDERATE_REMEMBER_TIMEOUT``: Time after which the cookie used for "remember my identity
  provider" expire. The default is ``604800``, one week. The cookie is called
  ``_remember_provider``.


New version warnings settings
-----------------------------

* ``CAS_NEW_VERSION_HTML_WARNING``: A boolean for diplaying a warning on html pages that a new
  version of the application is avaible. Once closed by a user, it is not displayed to this user
  until the next new version. The default is ``True``.
* ``CAS_NEW_VERSION_EMAIL_WARNING``: A boolean for sending a email to ``settings.ADMINS`` when a new
  version is available. The default is ``True``.


Tickets validity settings
-------------------------

* ``CAS_TICKET_VALIDITY``: Number of seconds the service tickets and proxy tickets are valid.
  This is the maximal time between ticket issuance by the CAS and ticket validation by an
  application. The default is ``60``.
* ``CAS_PGT_VALIDITY``: Number of seconds the proxy granting tickets are valid.
  The default is ``3600`` (1 hour).
* ``CAS_TICKET_TIMEOUT``: Number of seconds a ticket is kept in the database before sending
  Single Log Out request and being cleared. The default is ``86400`` (24 hours).

Tickets miscellaneous settings
------------------------------

* ``CAS_TICKET_LEN``: Default ticket length. All CAS implementations MUST support ST and PT
  up to 32 chars, PGT and PGTIOU up to 64 chars and it is RECOMMENDED that all tickets up
  to 256 chars are supported. Here the default is ``64``.
* ``CAS_LT_LEN``: Length of the login tickets. Login tickets are only processed by ``django-cas-server``
  thus there are no length restrictions on it. The default is ``CAS_TICKET_LEN``.
* ``CAS_ST_LEN``: Length of the service tickets. The default is ``CAS_TICKET_LEN``.
  You may need to lower it to ``32`` if you use some old clients.
* ``CAS_PT_LEN``: Length of the proxy tickets. The default is ``CAS_TICKET_LEN``.
  This length should be the same as ``CAS_ST_LEN``. You may need to lower it to ``32``
  if you use some old clients.
* ``CAS_PGT_LEN``: Length of the proxy granting tickets. The default is ``CAS_TICKET_LEN``.
* ``CAS_PGTIOU_LEN``: Length of the proxy granting tickets IOU. The default is ``CAS_TICKET_LEN``.

* ``CAS_LOGIN_TICKET_PREFIX``: Prefix of login tickets. The default is ``"LT"``.
* ``CAS_SERVICE_TICKET_PREFIX``: Prefix of service tickets. The default is ``"ST"``.
  The CAS specification mandates that service tickets MUST begin with the characters ST
  so you should not change this.
* ``CAS_PROXY_TICKET_PREFIX``: Prefix of proxy ticket. The default is ``"PT"``.
* ``CAS_PROXY_GRANTING_TICKET_PREFIX``: Prefix of proxy granting ticket. The default is ``"PGT"``.
* ``CAS_PROXY_GRANTING_TICKET_IOU_PREFIX``: Prefix of proxy granting ticket IOU. The default is ``"PGTIOU"``.


Mysql backend settings
----------------------
Deprecated, see the `Sql backend settings`_.
Only useful if you are using the mysql authentication backend:

* ``CAS_SQL_HOST``: Host for the SQL server. The default is ``"localhost"``.
* ``CAS_SQL_USERNAME``: Username for connecting to the SQL server.
* ``CAS_SQL_PASSWORD``: Password for connecting to the SQL server.
* ``CAS_SQL_DBNAME``: Database name.
* ``CAS_SQL_DBCHARSET``: Database charset. The default is ``"utf8"``
* ``CAS_SQL_USER_QUERY``: The query performed upon user authentication.
  The username must be in field ``username``, the password in ``password``,
  additional fields are used as the user attributes.
  The default is ``"SELECT user AS username, pass AS password, users.* FROM users WHERE user = %s"``
* ``CAS_SQL_PASSWORD_CHECK``: The method used to check the user password. Must be one of the following:

  * ``"crypt"`` (see <https://en.wikipedia.org/wiki/Crypt_(C)>), the password in the database
    should begin with $
  * ``"ldap"`` (see https://tools.ietf.org/id/draft-stroeder-hashed-userpassword-values-01.html)
    the password in the database must begin with one of {MD5}, {SMD5}, {SHA}, {SSHA}, {SHA256},
    {SSHA256}, {SHA384}, {SSHA384}, {SHA512}, {SSHA512}, {CRYPT}.
  * ``"hex_HASH_NAME"`` with ``HASH_NAME`` in md5, sha1, sha224, sha256, sha384, sha512.
    The hashed password in the database is compared to the hexadecimal digest of the clear
    password hashed with the corresponding algorithm.
  * ``"plain"``, the password in the database must be in clear.

  The default is ``"crypt"``.


Sql backend settings
--------------------
Only useful if you are using the sql authentication backend. You must add a ``"cas_server"``
database to `settings.DATABASES <https://docs.djangoproject.com/en/stable/ref/settings/#std:setting-DATABASES>`__
as defined in the django documentation. It is then the database
used by the sql backend.

* ``CAS_SQL_USER_QUERY``: The query performed upon user authentication.
  The username must be in field ``username``, the password in ``password``,
  additional fields are used as the user attributes.
  The default is ``"SELECT user AS username, pass AS password, users.* FROM users WHERE user = %s"``
* ``CAS_SQL_PASSWORD_CHECK``: The method used to check the user password. Must be one of the following:

  * ``"crypt"`` (see <https://en.wikipedia.org/wiki/Crypt_(C)>), the password in the database
    should begin with $
  * ``"ldap"`` (see https://tools.ietf.org/id/draft-stroeder-hashed-userpassword-values-01.html)
    the password in the database must begin with one of {MD5}, {SMD5}, {SHA}, {SSHA}, {SHA256},
    {SSHA256}, {SHA384}, {SSHA384}, {SHA512}, {SSHA512}, {CRYPT}.
  * ``"hex_HASH_NAME"`` with ``HASH_NAME`` in md5, sha1, sha224, sha256, sha384, sha512.
    The hashed password in the database is compared to the hexadecimal digest of the clear
    password hashed with the corresponding algorithm.
  * ``"plain"``, the password in the database must be in clear.

  The default is ``"crypt"``.
* ``CAS_SQL_PASSWORD_CHARSET``: Charset the SQL users passwords was hash with. This is needed to
  encode the user submitted password before hashing it for comparison. The default is ``"utf-8"``.


Ldap backend settings
---------------------
Only useful if you are using the ldap authentication backend:

* ``CAS_LDAP_SERVER``: Address of the LDAP server. The default is ``"localhost"``.
* ``CAS_LDAP_USER``: User bind address, for example ``"cn=admin,dc=crans,dc=org"`` for
  connecting to the LDAP server.
* ``CAS_LDAP_PASSWORD``: Password for connecting to the LDAP server.
* ``CAS_LDAP_BASE_DN``: LDAP search base DN, for example ``"ou=data,dc=crans,dc=org"``.
* ``CAS_LDAP_USER_QUERY``: Search filter for searching user by username. User entered usernames are
  escaped using ``ldap3.utils.conv.escape_bytes``. The default is ``"(uid=%s)"``
* ``CAS_LDAP_USERNAME_ATTR``: Attribute used for user's usernames. The default is ``"uid"``
* ``CAS_LDAP_PASSWORD_ATTR``: Attribute used for user's passwords. The default is ``"userPassword"``
* ``CAS_LDAP_PASSWORD_CHECK``: The method used to check the user password. Must be one of the following:

  * ``"crypt"`` (see <https://en.wikipedia.org/wiki/Crypt_(C)>), the password in the database
    should begin with $
  * ``"ldap"`` (see https://tools.ietf.org/id/draft-stroeder-hashed-userpassword-values-01.html)
    the password in the database must begin with one of {MD5}, {SMD5}, {SHA}, {SSHA}, {SHA256},
    {SSHA256}, {SHA384}, {SSHA384}, {SHA512}, {SSHA512}, {CRYPT}.
  * ``"hex_HASH_NAME"`` with ``HASH_NAME`` in md5, sha1, sha224, sha256, sha384, sha512.
    The hashed password in the database is compared to the hexadecimal digest of the clear
    password hashed with the corresponding algorithm.
  * ``"plain"``, the password in the database must be in clear.
  * ``"bind"``, the user credentials are used to bind to the ldap database and retreive the user
    attribute. In this mode, the settings ``CAS_LDAP_PASSWORD_ATTR`` and ``CAS_LDAP_PASSWORD_CHARSET``
    are ignored, and it is the ldap server that performs the password check.

  The default is ``"ldap"``.
* ``CAS_LDAP_ATTRS_VIEW``: This parameter is only used then ``CAS_LDAP_PASSWORD_CHECK`` is set to
  ``"bind"``. If ``0`` the user attributes are retrieved by connecting to the ldap as ``CAS_LDAP_USER``.
  If ``1`` the user attributes are retrieve then the user authenticate using the user credentials and
  are cached for later use. It means there can be some differences between the attributes in database
  and the cached ones. See the parameter ``CAS_TGT_VALIDITY`` to force user to reauthenticate
  periodically.
  The default is ``0``.
* ``CAS_LDAP_PASSWORD_CHARSET``: Charset the LDAP users passwords was hashed with. This is needed to
  encode the user submitted password before hashing it for comparison. The default is ``"utf-8"``.


Test backend settings
---------------------
Only useful if you are using the test authentication backend:

* ``CAS_TEST_USER``: Username of the test user. The default is ``"test"``.
* ``CAS_TEST_PASSWORD``: Password of the test user. The default is ``"test"``.
* ``CAS_TEST_ATTRIBUTES``: Attributes of the test user. The default is
  ``{'nom': 'Nymous', 'prenom': 'Ano', 'email': 'anonymous@example.net',
  'alias': ['demo1', 'demo2']}``.


Authentication backend
======================

``django-cas-server`` comes with some authentication backends:

* dummy backend ``cas_server.auth.DummyAuthUser``: all authentication attempts fail.
* test backend ``cas_server.auth.TestAuthUser``: username, password and returned attributes
  for the user are defined by the ``CAS_TEST_*`` settings.
* django backend ``cas_server.auth.DjangoAuthUser``: Users are authenticated against django users system.
  This is the default backend. The returned attributes are the fields available on the user model.
* mysql backend ``cas_server.auth.MysqlAuthUser``: Deprecated, use the sql backend instead.
  see the `Mysql backend settings`_ section. The returned attributes are those returned by sql query
  ``CAS_SQL_USER_QUERY``.
* sql backend ``cas_server.auth.SqlAuthUser``: see the `Sql backend settings`_ section.
  The returned attributes are those returned by sql query ``CAS_SQL_USER_QUERY``.
* ldap backend ``cas_server.auth.LdapAuthUser``: see the `Ldap backend settings`_ section.
  The returned attributes are those of the ldap node returned by the query filter ``CAS_LDAP_USER_QUERY``.
* federated backend ``cas_server.auth.CASFederateAuth``: It is automatically used when ``CAS_FEDERATE`` is ``True``.
  You should not set it manually without setting ``CAS_FEDERATE`` to ``True``.


Logs
====

``django-cas-server`` logs most of its actions. To enable login, you must set the ``LOGGING``
(https://docs.djangoproject.com/en/stable/topics/logging) variable in ``settings.py``.

Users successful actions (login, logout) are logged with the level ``INFO``, failures are logged
with the level ``WARNING`` and user attributes transmitted to a service are logged with the level ``DEBUG``.

For example to log to syslog you can use :

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

Service Patterns
================

In a CAS context, ``Service`` refers to the application the client is trying to access.
By extension we use ``service`` for the URL of such an application.

By default, ``django-cas-server`` does not allow any service to use the CAS to authenticate users.
In order to allow services, you need to connect to the django admin interface using a django
superuser, and add a first service pattern.

A service pattern comes with 9 fields:

* ``Position``: an integer used to change the order in which services are matched against
  service patterns.
* ``Name``: the name of the service pattern. It will be displayed to the users asking for a ticket
  for a service matching this service pattern on the login page.
* ``Pattern``: a regular expression used to match services.
* ``User field``: the user attribute to use as username for services matching this service pattern.
  Leave it empty to use the login name.
* ``Restrict username``: if checked, only login names defined below are allowed to get tickets
  for services matching this service pattern.
* ``Proxy``: if checked, allow the creation of Proxy Ticket for services matching this
  service pattern. Otherwise, only Service Ticket will be created.
* ``Proxy callback``: if checked, services matching this service pattern are allowed to retrieve Proxy
  Granting Ticket. A service with a Proxy Granting Ticket can get Proxy Ticket for other services.
  Hence you must only check this for trusted services that need it. (For instance, a webmail needs
  Proxy Ticket to authenticate himself as the user to the imap server).
* ``Single log out``: Check it to send Single Log Out requests to authenticated services matching
  this service pattern. SLO requests are sent to all services the user is authenticated to when
  the user disconnects.
* ``Single log out callback``: The http(s) URL to POST the SLO requests. If empty, the service URL
  is used. This field is useful to allow non http services (imap, smtp, ftp) to handle SLO requests.

A service pattern has 4 associated models:

* ``Usernames``: a list of username associated with the ``Restrict username`` field
* ``Replace attribute names``: a list of user attributes to send to the service. Choose the name
  used for sending the attribute by setting ``Replacement`` or leave it empty to leave it unchanged.
* ``Replace attribute values``: a list of sent user attributes for which value needs to be tweaked.
  Replace the attribute value by the string obtained by replacing the leftmost non-overlapping
  occurrences of ``pattern`` in string by ``replace``. In ``replace`` backslash escapes are processed.
  Matched groups are captured by \1, \2, etc.
* ``Filter attribute values``: a list of user attributes for which value needs to match a regular
  expression. For instance, service A may need an email address, and you only want user with
  an email address to connect to it. To do so, put ``email`` in ``Attribute`` and ``.*`` in ``pattern``.

When a user asks for a ticket for a service, the service URL is compared against each service pattern
sorted by ``position``. The first service pattern that matches the service URL is chosen.
Hence, you should give low ``position`` to very specific patterns like
``^https://www\.example\.com(/.*)?$`` and higher ``position`` to generic patterns like ``^https://.*``.
So the service URL ``https://www.examle.com`` will use the service pattern for
``^https://www\.example\.com(/.*)?$`` and not the one for ``^https://.*``.


Federation mode
===============

``django-cas-server`` comes with a federation mode. When ``CAS_FEDERATE`` is ``True``,
users are invited to choose an identity provider on the login page, then, they are redirected
to the provider CAS to authenticate. This provider transmits to ``django-cas-server`` the user
username and attributes. The user is now logged in on ``django-cas-server`` and can use
services using ``django-cas-server`` as CAS.

In federation mode, the user attributes are cached upon user authentication. See the settings
``CAS_TGT_VALIDITY`` to force users to reauthenticate periodically and allow ``django-cas-server``
to refresh cached attributes.

The list of allowed identity providers is defined using the django admin application.
With the development server started, visit http://127.0.0.1:8000/admin/ to add identity providers.

An identity provider comes with 5 fields:

* ``Position``: an integer used to tweak the order in which identity providers are displayed on
  the login page. Identity providers are sorted using position first, then, on equal position,
  using ``verbose name`` and then, on equal ``verbose name``, using ``suffix``.
* ``Suffix``: the suffix that will be append to the username returned by the identity provider.
  It must be unique.
* ``Server url``: the URL to the identity provider CAS. For instance, if you are using
  ``https://cas.example.org/login`` to authenticate on the CAS, the ``server url`` is
  ``https://cas.example.org``
* ``CAS protocol version``: the version of the CAS protocol to use to contact the identity provider.
  The default is version 3.
* ``Verbose name``: the name used on the login page to display the identity provider.
* ``Display``: a boolean controlling the display of the identity provider on the login page.
  Beware that this do not disable the identity provider, it just hide it on the login page.
  User will always be able to log in using this provider by fetching ``/federate/provider_suffix``.


In federation mode, ``django-cas-server`` build user's username as follow:
``provider_returned_username@provider_suffix``.
Choose the provider returned username for ``django-cas-server`` and the provider suffix
in order to make sense, as this built username is likely to be displayed to end users in
applications.


Then using federate mode, you should add one command to a daily crontab: ``cas_clean_federate``.
This command clean the local cache of federated user from old unused users.


You could for example do as below::

  10   0  * * * cas-user /path/to/project/manage.py cas_clean_federate



.. |travis| image:: https://badges.genua.fr/travis/com/nitmir/django-cas-server/master.svg
    :target: https://travis-ci.com/nitmir/django-cas-server

.. |pypi_version| image:: https://badges.genua.fr/pypi/v/django-cas-server.svg
    :target: https://pypi.org/project/django-cas-server/

.. |github_version| image:: https://badges.genua.fr/github/tag/nitmir/django-cas-server.svg?label=github
    :target: https://github.com/nitmir/django-cas-server/releases/latest

.. |licence| image:: https://badges.genua.fr/pypi/l/django-cas-server.svg
    :target: https://www.gnu.org/licenses/gpl-3.0.html

.. |codacy| image:: https://badges.genua.fr/codacy/grade/255c21623d6946ef8802fa7995b61366/master.svg
    :target: https://www.codacy.com/app/valentin-samir/django-cas-server

.. |coverage| image:: https://intranet.genua.fr/coverage/badge/django-cas-server/master.svg
    :target: https://badges.genua.fr/coverage/django-cas-server/master

.. |doc| image:: https://badges.genua.fr/local/readthedocs/?version=latest
    :target: http://django-cas-server.readthedocs.io
