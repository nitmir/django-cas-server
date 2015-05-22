=====
CAS Server
=====

CAS Server is a Django app implementing the CAS Protocol 3.0 Specification
(https://jasig.github.io/cas/development/protocol/CAS-Protocol-Specification.html)
By defaut, the authentication process use django internal users but you can easily
use any sources (see auth classes in the auth.py file)

The differents parametters you can use in settings.py to tweak the application
are listed in default_settings.py

The defaut login/logout template use django-bootstrap3 (https://github.com/dyve/django-bootstrap3)
but you can use your own templates using the CAS_LOGIN_TEMPLATE,
CAS_LOGGED_TEMPLATE and CAS_WARN_TEMPLATE.

Quick start
-----------

1. Add "cas_server" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = (
        ...
        'cas_server',
    )

2. Include the polls URLconf in your project urls.py like this::

    url(r'^cas/', include('cas_server.urls')),

3. Run `python manage.py migrate` to create the cas_server models.

4. Start the development server and visit http://127.0.0.1:8000/admin/
   to add a first service allowed to authenticate user agains the CAS
   (you'll need the Admin app enabled).

5. Visit http://127.0.0.1:8000/cas/ to login with your django users.
