CAS Server
##########

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

By default, the authentication process use django internal users but you can easily
use any sources (see auth classes in the auth.py file)

The default login/logout template use `django-bootstrap3 <https://github.com/dyve/django-bootstrap3>`__
but you can use your own templates using settings variables.

Note that for Django 1.7 compatibility, you need a version of
`django-bootstrap3 <https://github.com/dyve/django-bootstrap3>`__ < 7.0.0
like the 6.2.2 version.

.. contents:: Table of Contents

Features
========

* Support CAS version 1.0, 2.0, 3.0
* Support Single Sign Out
* Configuration of services via the django Admin application
* Fine control on which user's attributes are passed to which service
* Possibility to rename/rewrite attributes per service
* Possibility to require some attribute values per service
* Federated mode between multiple CAS
* Supports Django 1.7, 1.8 and 1.9
* Supports Python 2.7, 3.x

Dependencies
============

``django-cas-server`` depends on the following python packages:

* Django >= 1.7 < 1.10
* requests >= 2.4
* requests_futures >= 0.9.5
* django-picklefield >= 0.3.1
* django-bootstrap3 >= 5.4 (< 7.0.0 if using django 1.7)
* lxml >= 3.4
* six >= 1

Installation
============

The recommended installation mode is to use a virtualenv with ``--system-site-packages``

1. Make sure that python virtualenv is installed

2. Install python packages available via the system package manager:

   On debian like systems::

    $ sudo apt-get install python-django python-requests python-django-picklefield python-six python-lxml

   On debian jessie, you can use the version of python-django available in the
   `backports <https://backports.debian.org/Instructions/>`_.

   On centos like systems::

    $ sudo yum install python-django python-requests python-six python-lxml

3. Create a virtualenv::

    $ virtualenv --system-site-packages cas_venv
    Running virtualenv with interpreter /var/www/html/cas-server/bin/python2
    Using real prefix '/usr'
    New python executable in cas/bin/python2
    Also creating executable in cas/bin/python
    Installing setuptools, pip...done.
    $ cd cas_venv/; . bin/activate

4. Create a django project::

   $ django-admin startproject cas_project
   $ cd cas_project

5. Install `django-cas-server`. To use the last published release, run::

    $ pip install django-cas-server

   Alternatively if you want to use the version of the git repository, you can clone it::

    $ git clone https://github.com/nitmir/django-cas-server
    $ cd django-cas-server
    $ pip install -r requirements.txt

   Then, either run ``make install`` to create a python package using the sources of the repository
   and install it with pip, or place the `cas_server` directory into your
   `PYTHONPATH <https://docs.python.org/2/using/cmdline.html#envvar-PYTHONPATH>`_
   (for instance by symlinking `cas_server` to the root of your django project).

6. Open ``cas_project/settings.py`` in you favourite editor and follow the quick start section.


Quick start
===========

1. Add "cas_server" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = (
        'django.contrib.admin',
        ...
        'bootstrap3',
        'cas_server',
    )

   For internationalization support, add "django.middleware.locale.LocaleMiddleware"
   to your MIDDLEWARE_CLASSES setting like this::

    MIDDLEWARE_CLASSES = (
        ...
        'django.middleware.locale.LocaleMiddleware',
        ...
    )

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

5. Run ``python manage.py createsuperuser`` to create an administrator user.

6. Start the development server and visit http://127.0.0.1:8000/admin/
   to add a first service allowed to authenticate user against the CAS
   (you'll need the Admin app enabled). See the Service Patterns section bellow.

7. Visit http://127.0.0.1:8000/cas/ to login with your django users.




Settings
========

All settings are optional. Add them to ``settings.py`` to customize ``django-cas-server``:


Template settings
-----------------

* ``CAS_LOGO_URL``: URL to the logo showed in the up left corner on the default
  templates. Set it to ``False`` to disable it.

* ``CAS_LOGIN_TEMPLATE``: Path to the template showed on ``/login`` then the user
  is not autenticated.  The default is ``"cas_server/login.html"``.
* ``CAS_WARN_TEMPLATE``: Path to the template showed on ``/login?service=...`` then
  the user is authenticated and has asked to be warned before being connected
  to a service. The default is ``"cas_server/warn.html"``.
* ``CAS_LOGGED_TEMPLATE``: Path to the template showed on ``/login`` then to user is
  authenticated. The default is ``"cas_server/logged.html"``.
* ``CAS_LOGOUT_TEMPLATE``: Path to the template showed on ``/logout`` then to user
  is being disconnected. The default is ``"cas_server/logout.html"``
* ``CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT``: Should we redirect users to `/login` after they
  logged out instead of displaying ``CAS_LOGOUT_TEMPLATE``. The default is ``False``.


Authentication settings
-----------------------

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


Federation settings
-------------------

* ``CAS_FEDERATE``: A boolean for activating the federated mode (see the federate section below).
  The default is ``False``.
* ``CAS_FEDERATE_REMEMBER_TIMEOUT``: Time after witch the cookie use for "remember my identity
  provider" expire. The default is ``604800``, one week. The cookie is called
  ``_remember_provider``.


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


Mysql backend settings
----------------------
Only usefull if you are using the mysql authentication backend:

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
    should begin this $
  * ``"ldap"`` (see https://tools.ietf.org/id/draft-stroeder-hashed-userpassword-values-01.html)
    the password in the database must begin with one of {MD5}, {SMD5}, {SHA}, {SSHA}, {SHA256},
    {SSHA256}, {SHA384}, {SSHA384}, {SHA512}, {SSHA512}, {CRYPT}.
  * ``"hex_HASH_NAME"`` with ``HASH_NAME`` in md5, sha1, sha224, sha256, sha384, sha512.
    The hashed password in the database is compare to the hexadecimal digest of the clear
    password hashed with the corresponding algorithm.
  * ``"plain"``, the password in the database must be in clear.

  The default is ``"crypt"``.


Test backend settings
---------------------
Only usefull if you are using the test authentication backend:

* ``CAS_TEST_USER``: Username of the test user. The default is ``"test"``.
* ``CAS_TEST_PASSWORD``: Password of the test user. The default is ``"test"``.
* ``CAS_TEST_ATTRIBUTES``: Attributes of the test user. The default is
  ``{'nom': 'Nymous', 'prenom': 'Ano', 'email': 'anonymous@example.net',
  'alias': ['demo1', 'demo2']}``.


Authentication backend
======================

``django-cas-server`` comes with some authentication backends:

* dummy backend ``cas_server.auth.DummyAuthUser``: all authentication attempt fails.
* test backend ``cas_server.auth.TestAuthUser``: username, password and returned attributes
  for the user are defined by the ``CAS_TEST_*`` settings.
* django backend ``cas_server.auth.DjangoAuthUser``: Users are authenticated against django users system.
  This is the default backend. The returned attributes are the fields available on the user model.
* mysql backend ``cas_server.auth.MysqlAuthUser``: see the 'Mysql backend settings' section.
  The returned attributes are those return by sql query ``CAS_SQL_USER_QUERY``.
* federated backend ``cas_server.auth.CASFederateAuth``: It is automatically used then ``CAS_FEDERATE`` is ``True``.
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

By default, ``django-cas-server`` do not allow any service to use the CAS to authenticate users.
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
* ``Restrict username``: if checked, only login name defined below are allowed to get tickets
  for services matching this service pattern.
* ``Proxy``: if checked, allow the creation of Proxy Ticket for services matching this
  service pattern. Otherwise, only Service Ticket will be created.
* ``Proxy callback``: if checked, services matching this service pattern are allowed to retrieve Proxy
  Granting Ticket. A service with a Proxy Granting Ticket can get Proxy Ticket for other services.
  Hence you must only check this for trusted services that need it. (For instance, a webmail needs
  Proxy Ticket to authenticate himself as the user to the imap server).
* ``Single log out``: Check it to send Single Log Out requests to authenticated services matching
  this service pattern. SLO requests are send to all services the user is authenticated to then
  the user disconnect.
* ``Single log out callback``: The http(s) URL to POST the SLO requests. If empty, the service URL
  is used. This field is useful to allow non http services (imap, smtp, ftp) to handle SLO requests.

A service pattern has 4 associated models:

* ``Usernames``: a list of username associated with the ``Restrict username`` field
* ``Replace attribut names``: a list of user attributes to send to the service. Choose the name
  used for sending the attribute by setting ``Remplacement`` or leave it empty to leave it unchanged.
* ``Replace attribut values``: a list of sent user attributes for which value needs to be tweak.
  Replace the attribute value by the string obtained by replacing the leftmost non-overlapping
  occurrences of ``pattern`` in string by ``replace``. In ``replace`` backslash escapes are processed.
  Matched groups are captures by \1, \2, etc.
* ``Filter attribut values``: a list of user attributes for which value needs to match a regular
  expression. For instance, service A may need an email address, and you only want user with
  an email address to connect to it. To do so, put ``email`` in ``Attribute`` and ``.*`` in ``pattern``.

Then a user ask a ticket for a service, the service URL is compare against each service patterns
sorted by `position`. The first service pattern that matches the service URL is chosen.
Hence, you should give low `position` to very specific patterns like
``^https://www\.example\.com(/.*)?$`` and higher `position` to generic patterns like ``^https://.*``.
So the service URL `https://www.examle.com` will use the service pattern for
``^https://www\.example\.com(/.*)?$`` and not the one for ``^https://.*``.


Federation mode
===============

``django-cas-server`` comes with a federation mode. Then ``CAS_FEDERATE`` is ``True``,
user are invited to choose an identity provider on the login page, then, they are redirected
to the provider CAS to authenticate. This provider transmit to ``django-cas-server`` the user
username and attributes. The user is now logged in on ``django-cas-server`` and can use
services using ``django-cas-server`` as CAS.

The list of allowed identity providers is defined using the django admin application.
With the development server started, visit http://127.0.0.1:8000/admin/ to add identity providers.

An identity provider comes with 5 fields:

* ``Position``: an integer used to tweak the order in which identity providers are displayed on
  the login page. Identity providers are sorted using position first, then, on equal position,
  using ``verbose name`` and then, on equal ``verbose name``, using ``suffix``.
* ``Suffix``: the suffix that will be append to the username returned by the identity provider.
  It must be unique.
* ``Server url``: the URL to the identity provider CAS. For instance, if you are using
  ``https://cas.example.org/login`` to authenticate on the CAS, the `server url` is
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


You could for example do as bellow :

.. code-block::

    10   0  * * * cas-user /path/to/project/manage.py cas_clean_federate
