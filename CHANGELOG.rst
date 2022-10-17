Change Log
##########

All notable changes to this project will be documented in this file.

.. contents:: Table of Contents
   :depth: 2

v2.0.0 - 2022-10-17
===================

Added
-----
* Support for Django 4.0 and 4.1
* Add locale for zh_Hans
* Add a unit test with a non ascii char in service url
* Add settings to allow deletings Django cookies upon logout

Changed
-------
* Update CI: require pytest >= 7 and remove pytest-pythonpath dependancy

Fixes
-----
* Fix unicode sandwich issue in cas_server.utils.update_url
* Fix DeprecationWarning about default_app_config in Django 3.2
* Fix DeprecationWarning about USE_L10N in Django 4.0

Removed
-------
* Drop support for python 2.7 (now deprecated for more than 2 years,
  expect it to break now or in a near future)
* Drop support for python 3.5 (but it should keep working for a while.
  pytest >= 7 do not support python 3.5 and Debian Stretch support ended)


v1.3.1 - 2021-07-03
===================

Fixes
-----

* Documentation generation to works with latest Django and sphinx version
* Update classifier and dependencies versions in setup.py

v1.3.0 - 2021-06-19
===================

Added
-----

* Support for Dango 3.1 and 3.2
* Implement CAS_LDAP_ATTRS_VIEW set to 0: then using ldap bind mode, user
  attributes can be retreive either using CAS_LDAP_USER or using the
  binded user credentials.
* Added ppc64le architecture support on travis-ci (django-cas-server is
  included in the ppc64le versions of RHEL and Ubuntu)
* Python 3.9 support

Fixes
-----

* Allow to use user attributes if auth by ldap bind
* Fix spelling mistakes in french translation
* Fix bug model datefield Form (Federated User Admin)
* django.conf.urls is deprecated and will be removed in Django 4.0.
  Use django.urls.re_path instead

Removed
-------

* Drop support for Django 3.0 as it reached end of life.

v1.2.0 - 2020-07-05
===================

Added
-----

* Bootstrap 4 templates
* Support for Django 2.2 and 3.0

Fixes
-----

* Replace calls to add_description_unit. As of Sphinx 2.4, the deprecated
  add_description_unit function has been removed.
* Fix CRYPT-DES hash method for LDAP
* Fix various spelling miskate in README.rst
* Service URL: keep blank GET arguments

Changed
-------

* Use python3 for flake8, check_rst and coverage
* Update README.rst quickstart for using python3 by default

Removed
-------

* Drop support for Django 2.0 and 2.1 as it reached end of life.
  We still keep Django 1.11 as it is the last supported release
  by python2 AND the currently packaged version of Django in
  Debian Buster (current stable).

v1.1.0 - 2019-03-02
===================

Added
-----

* Support for Django 2.1

Fixes
-----

* Checkbox position on the login page
* Set ldap3 client_strategy from sync to sync-restartable
* Deprecation warning for {% load staticfiles %} and django.contrib.staticfiles

v1.0.0 - 2019-01-12
===================

Added
-----

* Support for python 3.6 and Django 1.11
* Support for Django 2.0
* Keep query string then redirecting from / to /login

Fixes
-----

* Add missing attributes authenticationDate, longTermAuthenticationRequestTokenUsed and
  isFromNewLogin from service validation response
* Catch error from calling django.contrib.staticfiles.templatetags.staticfiles.static
  in non-debug mode before collectstatic in cas_server.default_settings.py
* Invalid escape sequence in regular expression

Deprecated
----------

* Support for Django <1.11 is dropped, it should still works for this version.
  Next versions will most probably be not compatible with Django <1.11
* Support for python 3.4 is dropped, it should still works for this version.
  Next versions may or may not works with python 3.4.

Other
-----

* Migrations have been squashed for Django 2.0 support. Be sur to apply all migration before
  updating to this version
* Update PyPi url from https://pypi.python.org to https://pypi.org

v0.9.0 - 2017-11-17
===================

Added
-----
* Dutch translation
* Protuguese translation (brazilian variant)
* Support for ldap3 version 2 or more (changes in the API)
  All exception are now in ldap3.core.exceptions, methodes for fetching attritutes and
  dn are renamed.
* Possibility to disable service message boxes on the login pages

Fixed
-----
* Then using the LDAP auth backend with ``bind`` method for password check, do not try to bind
  if the user dn was not found. This was causing the exception
  ``'NoneType' object has no attribute 'getitem'`` describe in #21
* Increase the max size of usernames (30 chars to 250)
* Fix XSS js injection


v0.8.0 - 2017-03-08
===================

Added
-----
* Add a test for login with missing parameter (username or password or both)
* Add ldap auth using bind method (use the user credentials to bind the the ldap server and let the
  server check the credentials)
* Add CAS_TGT_VALIDITY parameter: Max time after with the user MUST reauthenticate.

Fixed
-----
* Allow both unicode and bytes dotted string in utils.import_attr
* Fix some spelling and grammar on log messages. (thanks to Allie Micka)
* Fix froms css class error on success/error due to a scpaless block
* Disable pip cache then installing with make install

Changed
-------
* Update french translation


v0.7.4 - 2016-09-07
===================

Fixed
-----
* Add templatetags to Pypi package


v0.7.3 - 2016-09-07
===================

Added
-----
* Add autofocus to the username input on the login page

Fixed
-----
* Really pick the last version on Pypi for new version checking.
  We were only sorting version string lexicographically and it would have break when
  we reach version 0.10.N or 0.N.10
* Only check for valid username/password if username and password POST fields are posted.
  This fix a bug where posting without it raise a exception are None where passed for
  username/password verification.


v0.7.2 - 2016-08-31
===================

Added
-----
* Add Django 1.10 support
* Add support of gitlab continuous integration

Fixed
-----
* Fix BootsrapForm: placeholder on Input and Textarea only, use class form-control on
  Input, Select and Textarea.
* Fix lang attribute in django 1.7. On html pages, the lang attribute of the <html> was not
  present in django 1.7. We use now a methode to display it that is also available in django 1.7


v0.7.1 - 2016-08-24
===================

Added
-----
* Add a forgotten migration (only change help_text and validators)


v0.7.0 - 2016-08-24
===================

Added
-----
* Add a CHANGELOG.rst file.
* Add a validator to models CharField that should be regular expressions checking that user input
  are valids regular expressions.
* Add a CAS_INFO_MESSAGES and CAS_INFO_MESSAGES_ORDER settings allowing to display messages in
  info-boxes on the html pages of the default templates.

Changed
-------
* Allow the user defined CAS_COMPONENT_URLS to omit not changed values.
* replace code-block without language indication by literal blocks.
* Update french translation

Fixed
-----
* Some README.rst typos.
* some english typos


v0.6.4 - 2016-08-14
===================

commit: 282e3a831b3c0b0818881c2f16d056850d572b89

Added
-----
* Add a forgotten migration (only change help_text)


v0.6.3 - 2016-08-14
===================

commit: 07a537b403c5c5e39a4ddd084f90e3a4de88a54e

Added
-----
* Add powered by footer
* Add a github version badge
* documents templatetags

Changed
-------
* Usage of the documented API for models _meta in auth.DjangoAuthUser
* set warn cookie using javascript if possible
* Unfold many to many attributes in auth.DjangoAuthUser attributes

Fixed
-----
* typos in README.rst
* w3c validation

Cleaned
-------
* Code factorisation (models.py, views.py)


v0.6.2 - 2016-08-02
===================

commit: 773707e6c3c3fa20f697c946e31cafc591e8fee8

Added
-----
* Support authentication renewal in federate mode
* Add new version email and info box then new version is available
* Add SqlAuthUser and LdapAuthUser auth classes.
  Deprecate the usage of MysqlAuthUser in favor of SqlAuthUser.
* Add pytest-warning to tests
* Add a checkbox to forget the identity provider if we checked "remember the identity provider"
* Add dependancies correspondance between python pypi, debian and centos packages in README

Changed
-------
* Move coverage computation last in travis
* Enable logging to stderr then running tests
* Remember "warn me before…" using a cookie
* Put favicon (shortcut icon) URL in settings

Deprecated
----------
* The auth class MysqlAuthUser is deprecated in favor of the SqlAuthUser class.

Fixed
-----
* Use custom templatetags instead settings custom attributes to Boundfields
  (As it do not work with django 1.7)
* Display an error message on bad response from identity provider in federate mode
  instead of crashing. (e.g. Bad XML document)
* Catch base64 decode error on b64decode to raise our custom exception BadHash
* Add secret as sensitive variables/post parameter for /auth
* Only set "remember my provider" in federated mode upon successful authentication
* Since we drop django-boostrap3 dependancies, Django default minimal version is 1.7.1
* [cas.py] Append renew=true when validating tickets

Cleaned
-------
* code factorization (cas.py, forms.py)


v0.6.1 - 2016-07-27
===================

commit: b168e0a6423c53de31aae6c444fa1d1c5083afa6

Added
-----
* Add sphinx docs + autodoc
* Add the possibility to run tests with "setup.py test"
* Include docs, Makefile, coverage config and tests config to source package
* Add serviceValidate ProxyTicket tests
* Add python 3.5 tox/travis tests

Changed
-------
* Use https://badges.genua.fr for badges

Fixed
-----
* Keep LoginTicket list upon fail authentication
  (It prevent the next login attemps to fail because of bad LT)

Cleaned
-------
* Compact federated mode migration
* Reformat default_settings.py for documentation using sphinx autodoc
* Factorize some code (from views.py to Ticket models class methods)
* Update urlpattern for django 1.10
* Drop dependancies django-picklefield and django-bootstrap3


v0.6.0 - 2016-07-06
===================

commit: 4ad4d13baa4236c5cd72cc5216d7ff08dd361476

Added
-----
* Add a section describing service patterns options to README.rst
* Add a federation mode:
  When the settings CAS_FEDERATE is True, django-cas-server will offer to the user to choose its
  CAS backend to authenticate. Hence the login page do not display anymore a username/password form
  but a select form with configured CASs backend.
  This allow to give access to CAS supported applications to users from multiple organization
  seamlessly.

  It was originally developped to mach the need of https://ares.fr (Federated CAS at
  https://cas.ares.fr, example of an application using it as https://chat.myares.fr)

Fixed
-----
* Then a ticket was marked as obtained with the user entering its credentials (aka not by SSO), and
  the service did not require it, ticket validation was failing. Now, if the service do not require
  authentication to be renewed, both ticket with renewed authentication and non renewed
  authentication validate successfully.



v0.5.0 - 2016-07-01
===================

commit: e3ab64271b718a17e4cbbbabda0a2453107a83df

Added
-----
* Add more password scheme support to the mysql authentication backend: ldap user
  attribute scheme encoding and simple password hash in hexa for md5, sha1, sha224,
  sha256, sha384, sha512.
* Add a main heading to template "Central Authentication Service" with a logo controled
  by CAS_LOGO_URL
* Add logos to the project (svg, png)
* Add coverage computation
* link project to codacy
* Update doc: add debian requirement, correct typos, correct links

Changed
-------
* Use settings to set tests username password and attributes
* Tweak the css and html for small screens
* Update travis cache for faster build
* clean Makefile, use pip to install, add target for tests

Fixed
-----
* Fix "warn me": we generate the ticket after the user agree to be connected to the service.
  we were generating first and the connect button was a link to the service url with the ?ticket=
  this could lead to situation where the ticket validity expire if the user is slow to click the
  connect button.
* Fix authentication renewal: the renew parameter were not transmited when POST the login request
   and self.renew (aks for auth renewal) was use instead of self.renewed (auth was renewd)
   when generating a ticket.
* Fix attribute value replacement when generating a ticket: we were using the 'name' attribute
  instead of the 'attribut' attribut on ReplaceAttributValue
* Fix attribute value replacement when generating a ticket then the value is a list: iterate over
  each element of the list.
* Fix a NameError in utils.import_attr
* Fix serviceValidate and samlValidate when user_field is an attribute that is a list: we use
  the first element of the list as username. we were serializing the list before that.
* Correct typos


Cleaned
-------
* Clean some useless conditional branches found with coverage
* Clean cas.js: use compact object declararion
* Use six for python{2|3} compatibility
* Move all unit tests to cas_server.tests and use django primitive. We also have a 100% tests
  coverage now. Using the django classes for tests, we do not need to use our own dirty mock.
* Move mysql backend password check to a function in utils


v0.4.4 - 2016-04-30
===================

commit: 77d1607b0beefe8b171adcd8e2dcd974e3cdc72a

Added
-----
* Add sensitive_post_parameters and sensitive_variables for passwords, so passwords are anonymised
  before django send an error report.
  
Fixed
-----
* Before commit 77fc5b5 the User model had a foreign key to the Session model. After the commit,
  Only the session_key is store, allowing to use different backend than the Session SQL backend.
  So the first migration (which is 21 migrations combined) was creating the User model with the
  foreign key, then delete it and add the field session_key. Somehow, MySQL did not like it.
  Now the first migration directly create the User model with the session_key and without the
  foreign key to the Session SQL backend.
* Evaluate attributes variables in the template samlValidate.xml. the {{ }} was missing causing
  the variable name to be displyed instead of the variable content.
* Return username in CAS 1.0 on the second ligne of the CAS response as specified.


Changed
-------
* Update tests


v0.4.3 - 2016-03-18
===================

commit: f6d436acb49f8d32b5457c316c18c4892accfd3b

Fixed
-----
* Currently, one of our dependancy, django-boostrap3, do not support django 1.7 in its last version.
  So there is some detection of the current django installed version in setup.py to pin 
  django-boostrap3 to a version supported by django 1.7 if django 1.7 is installed, or to require
  at least django 1.8.
  The detection did not handle the case where django was not installed.
* [PEP8] Put line breaks after binary operator and not before.


v0.4.2 - 2016-03-18
===================

commit: d1cd17d6103281b03a8c57013671057eab80d21c

Added
-----
* On logout, display the number of sessions we are logged out from.

Fixed
-----
* One of our dependancy, django-boostrap3, do not support django 1.7 in its last version.
  Some django version detection is added to setup.py to handle that.
* Some typos
* Make errors returned by utils.import_attr clearer (as they are likely to be displayed to the
  django admin)


v0.4.1 - 2015-12-23
===================

commit: 5e63f39f9b7c678a300ad2f8132166be34d1d35b

Added
-----
* Add a run_test_server target to make file. Running make run_test_server will build a virtualenv,
  create a django projet with django-cas-server and lauch ./management.py runserver. It is quite
  handy to test developement version.
* Add verbose name for cas_server app and models
* Add Makefile clean targets for tox tests and test virtualenv.
* Add link on license badge to the GPLv3

Changed
-------
* Make Makefile clean targets modular
* Use img.shields.io for PyPi badges
* Get django-cas-server version in Makefile directly from setup.py (so now, the version is only
  written in one place)

Fixed
-----
* Fix MysqlAuthUser when number of results != 1: In that case, call super anyway this the provided
  username.


v0.4.0 - 2015-12-15
===================

commit: 7b4fac575449e50c2caff07f5798dba7f4e4857c

Added
-----
* Add a help_text to pattern of ServicePattern
* Add a timeout to SLO requests
* Add logging capabilities (see README.rst for instruction)
* Add management commands that should be called on a regular basis to README.rst


v0.3.5 - 2015-12-12
===================

commit: 51fa0861f550723171e52d58025fa789dccb8cde

Added
-----
* Add badges to README.rst
* Document settings parameter in README.rst
* Add a "Features" section in README.rst

Changed
-------
* Add a AuthUser auth class and use it as auth classes base class instead of DummyAuthUser

Fixed
-----
* Fix minor errors and typos in README.rst



v0.3.4 - 2015-12-12
===================

commit: 9fbfe19c550b147e8d0377108cdac8231cf0fb27

Added
-----
* Add static files, templates and locales to the PyPi release by adding them to MANIFEST.in
* Add a Makefile with the build/install/clean/dist targets


v0.3.3 - 2015-12-12
===================

commit: 16b700d0127abe33a1eabf5d5fe890aeb5167e5a

Added
-----
* Add management commands and migrations to the package by adding there packages to setup.py
  packages list.
  

v0.3.2 - 2015-12-12 [YANKED]
============================

commit: eef9490885bf665a53349573ddb9cbe844319b3e

Added
-----
* Add migrations to setup.py package_data


v0.3.1 - 2015-12-12
===================

commit: d0f6ed9ea3a4b3e2bf715fd218c460892c32e39f

Added
-----
* Add a forgotten migration (remove auto_now_add=True from the User model)


v0.3.0 - 2015-12-12
===================

commit: b69769d71a99806a69e300eca0d7c6744a2b327e

Added
-----
* Django 1.9 compatibility (add tox and travis tests and fix some decrecated)


v0.2.1 - 2015-12-12
===================

commit: 90e077dedb991d651822e9bb283470de8bddd7dd

First github and PyPi release

Fixed
-----
* Prune .tox in MANIFEST.in
* add dist/ to .gitignore
* typo in setup.cfg


v0.2.0 - 2015-12-12 [YANKED]
============================

commit: a071ad46d7cd76fc97eb86f2f538d330457c6767


v0.1.0 - 2015-05-22 [YANKED]
============================

commit: 6981433bdf8a406992ba0c5e844a47d06ccc08fb
