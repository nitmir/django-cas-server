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
# (c) 2016 Valentin Samir
"""Tests module for views"""
from cas_server.default_settings import settings

import django
from django.test import TestCase, Client
from django.test.utils import override_settings
from django.utils import timezone


import random
import json
import mock
from lxml import etree
from six.moves import range

from cas_server import models
from cas_server import utils
from cas_server.tests.utils import (
    copy_form,
    get_login_page_params,
    get_auth_client,
    get_user_ticket_request,
    get_pgt,
    get_proxy_ticket,
    get_validated_ticket,
    HttpParamsHandler,
    Http404Handler
)
from cas_server.tests.mixin import BaseServicePattern, XmlContent, CanLogin


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class LoginTestCase(TestCase, BaseServicePattern, CanLogin):
    """Tests for the login view"""
    def setUp(self):
        """Prepare the test context:"""
        # we prepare a bunch a service url and service patterns for tests
        self.setup_service_patterns()

    @override_settings(CAS_NEW_VERSION_HTML_WARNING=True)
    @mock.patch("cas_server.utils.last_version", lambda: "1.2.3")
    @mock.patch("cas_server.utils.VERSION", "0.1.2")
    def test_new_version_available_ok(self):
        """test the new version info box"""
        client = Client()
        response = client.get("/login")
        self.assertIn(b"A new version of the application is available", response.content)

    @override_settings(CAS_NEW_VERSION_HTML_WARNING=True)
    @mock.patch("cas_server.utils.last_version", lambda: None)
    @mock.patch("cas_server.utils.VERSION", "0.1.2")
    def test_new_version_available_badpypi(self):
        """
            test the new version info box if pypi is not available (unable to retreive last version)
        """
        client = Client()
        response = client.get("/login")
        self.assertNotIn(b"A new version of the application is available", response.content)

    @override_settings(CAS_NEW_VERSION_HTML_WARNING=False)
    def test_new_version_available_disabled(self):
        """test the new version info box is disabled"""
        client = Client()
        response = client.get("/login")
        self.assertNotIn(b"A new version of the application is available", response.content)

    @override_settings(CAS_INFO_MESSAGES_ORDER=["cas_explained"])
    def test_messages_info_box_enabled(self):
        """test that the message info-box is displayed then enabled"""
        client = Client()
        response = client.get("/login")
        self.assertIn(
            b"The Central Authentication Service grants you access to most of our websites by ",
            response.content
        )

    @override_settings(CAS_INFO_MESSAGES_ORDER=[])
    def test_messages_info_box_disabled(self):
        """test that the message info-box is not displayed then disabled"""
        client = Client()
        response = client.get("/login")
        self.assertNotIn(
            b"The Central Authentication Service grants you access to most of our websites by ",
            response.content
        )

    # test1 and test2 are malformed and should be ignored, test3 is ok, test5 do not
    # exists and should be ignored
    @override_settings(CAS_INFO_MESSAGES_ORDER=["test1", "test2", "test3", "test5"])
    @override_settings(CAS_INFO_MESSAGES={
        "test1": "test",  # not a dict, should be ignored
        "test2": {"type": "success"},  # not "message" key, should be ignored
        "test3": {"message": "test3"},
        "test4": {"message": "test4"},
    })
    def test_messages_info_box_bad_messages(self):
        """test that mal formated messages dict are ignored"""
        client = Client()
        # not errors should be raises
        response = client.get("/login")
        # test3 is ok est should be there
        self.assertIn(b"test3", response.content)
        # test4 is not in CAS_INFO_MESSAGES_ORDER and should not be there
        self.assertNotIn(b"test4", response.content)

    def test_login_view_post_goodpass_goodlt(self):
        """Test a successul login"""
        # we get a client who fetch a frist time the login page and the login form default
        # parameters
        client, params = get_login_page_params()
        # we set username/password in the form
        params["username"] = settings.CAS_TEST_USER
        params["password"] = settings.CAS_TEST_PASSWORD
        # the LoginTicket in the form should match a valid LT in the user session
        self.assertTrue(params['lt'] in client.session['lt'])

        # we post a login attempt
        response = client.post('/login', params)
        # as username/password/lt are all valid, the login should succed
        self.assert_logged(client, response)
        # The LoginTicket is conssumed and should no longer be valid
        self.assertTrue(params['lt'] not in client.session['lt'])

    def test_login_post_missing_params(self):
        """Test a login attempt with missing POST parameters (username or password or both)"""
        # we get a client who fetch a frist time the login page and the login form default
        # parameters
        client, params = get_login_page_params()
        # we set only set username
        params["username"] = settings.CAS_TEST_USER
        # we post a login attempt
        response = client.post('/login', params)
        # as the LT is not valid, login should fail
        self.assert_login_failed(client, response)

        # we get a client who fetch a frist time the login page and the login form default
        # parameters
        client, params = get_login_page_params()
        # we set only set password
        params["password"] = settings.CAS_TEST_PASSWORD
        # we post a login attempt
        response = client.post('/login', params)
        # as the LT is not valid, login should fail
        self.assert_login_failed(client, response)

        # we get a client who fetch a frist time the login page and the login form default
        # parameters
        client, params = get_login_page_params()
        # we set neither username nor password
        # we post a login attempt
        response = client.post('/login', params)
        # as the LT is not valid, login should fail
        self.assert_login_failed(client, response)

    def test_login_view_post_goodpass_goodlt_warn(self):
        """Test a successul login requesting to be warned before creating services tickets"""
        # get a client and initial login params
        client, params = get_login_page_params()
        # set valids usernames/passswords
        params["username"] = settings.CAS_TEST_USER
        params["password"] = settings.CAS_TEST_PASSWORD
        # this time, we check the warn checkbox
        params["warn"] = "on"

        # postings login request
        response = client.post('/login', params)
        # as username/password/lt are all valid, the login should succed and warn be enabled
        self.assert_logged(client, response, warn=True)

    def test_lt_max(self):
        """Check we only keep the last 100 Login Ticket for a user"""
        # get a client and initial login params
        client, params = get_login_page_params()
        # get a first LT that should be valid
        current_lt = params["lt"]
        # we keep the last 100 generated LT by user, so after having generated `i_in_test` we
        # test if `current_lt` is still valid
        i_in_test = random.randint(0, 99)
        # after `i_not_in_test` `current_lt` should be valid not more
        i_not_in_test = random.randint(101, 150)
        # start generating 150 LT
        for i in range(150):
            if i == i_in_test:
                # before more than 100 LT generated, the first TL should be valid
                self.assertTrue(current_lt in client.session['lt'])
            if i == i_not_in_test:
                # after more than 100 LT generated, the first LT should be valid no more
                self.assertTrue(current_lt not in client.session['lt'])
                # assert that we do not keep more that 100 valid LT
                self.assertTrue(len(client.session['lt']) <= 100)
            # generate a new LT by getting the login page
            client, params = get_login_page_params(client)
        # in the end, we still have less that 100 valid LT
        self.assertTrue(len(client.session['lt']) <= 100)

    def test_login_view_post_badlt(self):
        """Login attempt with a bad LoginTicket, login should fail"""
        # get a client and initial login params
        client, params = get_login_page_params()
        # set valid username/password
        params["username"] = settings.CAS_TEST_USER
        params["password"] = settings.CAS_TEST_PASSWORD
        # set a bad LT
        params["lt"] = 'LT-random'

        # posting the login request
        response = client.post('/login', params)

        # as the LT is not valid, login should fail
        self.assert_login_failed(client, response)
        # the reason why login has failed is displayed to the user
        self.assertTrue(b"Invalid login ticket" in response.content)

    def test_login_view_post_badpass_good_lt(self):
        """Login attempt with a bad password"""
        # get a client and initial login params
        client, params = get_login_page_params()
        # set valid username but invalid password
        params["username"] = settings.CAS_TEST_USER
        params["password"] = "test2"
        # posting the login request
        response = client.post('/login', params)

        # as the password is wrong, login should fail
        self.assert_login_failed(client, response)
        # the reason why login has failed is displayed to the user
        self.assertTrue(
            (
                b"The credentials you provided cannot be "
                b"determined to be authentic"
            ) in response.content
        )

    def assert_ticket_attributes(self, client, ticket_value):
        """check the ticket attributes in the db"""
        # Get get current session user in the db
        user = models.User.objects.get(
            username=settings.CAS_TEST_USER,
            session_key=client.session.session_key
        )
        # we should find exactly one user
        self.assertTrue(user)
        # get the ticker object corresponting to `ticket_value`
        ticket = models.ServiceTicket.objects.get(value=ticket_value)
        # chek that the ticket is well attributed to the user
        self.assertEqual(ticket.user, user)
        # check that the user attributes match the attributes registered on the ticket
        self.assertEqual(ticket.attributs, settings.CAS_TEST_ATTRIBUTES)
        # check that the ticket has not being validated yet
        self.assertEqual(ticket.validate, False)
        # check that the service pattern registered on the ticket is the on we use for tests
        self.assertEqual(ticket.service_pattern, self.service_pattern)

    def assert_service_ticket(self, client, response, service="https://www.example.com"):
        """check that a ticket is well emited when requested on a allowed service"""
        # On ticket emission, we should be redirected to the service url, setting the ticket
        # GET parameter
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.has_header('Location'))
        self.assertTrue(
            response['Location'].startswith(
                "%s?ticket=%s-" % (service, settings.CAS_SERVICE_TICKET_PREFIX)
            )
        )
        # check that the value of the ticket GET parameter match the value of the ticket
        # created in the db
        ticket_value = response['Location'].split('ticket=')[-1]
        self.assert_ticket_attributes(client, ticket_value)

    def test_view_login_get_allowed_service(self):
        """Request a ticket for an allowed service by an unauthenticated client"""
        # get a bare new http client
        client = Client()
        # we are not authenticated and are asking for a ticket for https://www.example.com
        # which is a valid service matched by self.service_pattern
        response = client.get("/login?service=https://www.example.com")
        # the login page should be displayed
        self.assertEqual(response.status_code, 200)
        # we warn the user why it need to authenticated
        self.assertTrue(
            (
                b"Authentication required by service "
                b"example (https://www.example.com)"
            ) in response.content
        )

    @override_settings(CAS_SHOW_SERVICE_MESSAGES=False)
    def test_view_login_get_allowed_service_no_message(self):
        """Request a ticket for an allowed service by an unauthenticated client"""
        # get a bare new http client
        client = Client()
        # we are not authenticated and are asking for a ticket for https://www.example.com
        # which is a valid service matched by self.service_pattern
        response = client.get("/login?service=https://www.example.com")
        # the login page should be displayed
        self.assertEqual(response.status_code, 200)
        # we warn the user why it need to authenticated
        self.assertFalse(
            (
                b"Authentication required by service "
                b"example (https://www.example.com)"
            ) in response.content
        )

    def test_view_login_get_denied_service(self):
        """Request a ticket for an denied service by an unauthenticated client"""
        # get a bare new http client
        client = Client()
        # we are not authenticated and are asking for a ticket for https://www.example.net
        # which is NOT a valid service
        response = client.get("/login?service=https://www.example.net")
        self.assertEqual(response.status_code, 200)
        # we warn the user that https://www.example.net is not an allowed service url
        self.assertTrue(b"Service https://www.example.net not allowed" in response.content)

    @override_settings(CAS_SHOW_SERVICE_MESSAGES=False)
    def test_view_login_get_denied_service_no_message(self):
        """Request a ticket for an denied service by an unauthenticated client"""
        # get a bare new http client
        client = Client()
        # we are not authenticated and are asking for a ticket for https://www.example.net
        # which is NOT a valid service
        response = client.get("/login?service=https://www.example.net")
        self.assertEqual(response.status_code, 200)
        # we warn the user that https://www.example.net is not an allowed service url
        self.assertFalse(b"Service https://www.example.net not allowed" in response.content)

    def test_view_login_get_auth_allowed_service(self):
        """
        Request a ticket for an allowed service by an authenticated client containing
        non ascii char in url
        """
        # get a client that is already authenticated
        client = get_auth_client()
        # ask for a ticket for https://www.example.com
        response = client.get("/login?service=https://www.example.com/é")
        # as https://www.example.com/é is a valid service a ticket should be created and the
        # user redirected to the service url
        self.assert_service_ticket(client, response, service="https://www.example.com/%C3%A9")

    def test_view_login_get_auth_allowed_service_non_ascii(self):
        """Request a ticket for an allowed service by an authenticated client"""
        # get a client that is already authenticated
        client = get_auth_client()
        # ask for a ticket for https://www.example.com
        response = client.get("/login?service=https://www.example.com")
        # as https://www.example.com is a valid service a ticket should be created and the
        # user redirected to the service url
        self.assert_service_ticket(client, response)

    def test_view_login_get_auth_allowed_service_warn(self):
        """Request a ticket for an allowed service by an authenticated client"""
        # get a client that is already authenticated and has ask to be warned befor we
        # generated a ticket
        client = get_auth_client(warn="on")
        # ask for a ticket for https://www.example.com
        response = client.get("/login?service=https://www.example.com")
        # we display a warning to the user, asking him to validate the ticket creation (insted
        # a generating and redirecting directly to the service url)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"Authentication has been required by service "
                b"example (https://www.example.com)"
            ) in response.content
        )
        # get the displayed form parameters
        params = copy_form(response.context["form"])
        # we post, confirming we want a ticket
        response = client.post("/login", params)
        # as https://www.example.com is a valid service a ticket should be created and the
        # user redirected to the service url
        self.assert_service_ticket(client, response)

    def test_view_login_get_auth_denied_service(self):
        """Request a ticket for a not allowed service by an authenticated client"""
        # get a client that is already authenticated
        client = get_auth_client()
        # we are authenticated and are asking for a ticket for https://www.example.org
        # which is NOT a valid service
        response = client.get("/login?service=https://www.example.org")
        self.assertEqual(response.status_code, 200)
        # we warn the user that https://www.example.net is not an allowed service url
        # NO ticket are created
        self.assertTrue(b"Service https://www.example.org not allowed" in response.content)

    def test_user_logged_not_in_db(self):
        """If the user is logged but has been delete from the database, it should be logged out"""
        # get a client that is already authenticated
        client = get_auth_client()
        # delete the user in the db
        models.User.objects.get(
            username=settings.CAS_TEST_USER,
            session_key=client.session.session_key
        ).delete()
        # fetch the login page
        response = client.get("/login")

        # The user should be logged out
        self.assert_login_failed(client, response, code=302)
        # and redirected to the login page. We branch depending on the version a django as
        # the test client behaviour changed after django 1.9
        if django.VERSION < (1, 9):  # pragma: no cover coverage is computed with dango 1.9
            self.assertEqual(response["Location"], "http://testserver/login")
        else:
            self.assertEqual(response["Location"], "/login?")

    def test_service_restrict_user(self):
        """Testing the restric user capability from a service"""
        # get a client that is already authenticated
        client = get_auth_client()

        # trying to get a ticket from a service url matched by a service pattern having a
        # restriction on the usernames allowed to get tickets. the test user username is not one
        # of this username.
        response = client.get("/login", {'service': self.service_restrict_user_fail})
        self.assertEqual(response.status_code, 200)
        # the ticket is not created and a warning is displayed to the user
        self.assertTrue(b"Username not allowed" in response.content)

        # same but with the tes user username being one of the allowed usernames
        response = client.get("/login", {'service': self.service_restrict_user_success})
        # the ticket is created and we are redirected to the service url
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response["Location"].startswith("%s?ticket=" % self.service_restrict_user_success)
        )

    def test_service_filter(self):
        """Test the filtering on user attributes"""
        # get a client that is already authenticated
        client = get_auth_client()

        # trying to get a ticket from a service url matched by a service pattern having
        # a restriction on the user attributes. The test user if ailing these restrictions
        # We try first with a single value attribut (aka a string) and then with
        # a multi values attributs (aka a list of strings)
        for service in [self.service_filter_fail, self.service_filter_fail_alt]:
            response = client.get("/login", {'service': service})
            # the ticket is not created and a warning is displayed to the user
            self.assertEqual(response.status_code, 200)
            self.assertTrue(b"User characteristics not allowed" in response.content)

        # same but with rectriction that a valid upon the test user attributes
        response = client.get("/login", {'service': self.service_filter_success})
        # the ticket us created and the user redirected to the service url
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("%s?ticket=" % self.service_filter_success))

    def test_service_user_field(self):
        """Test using a user attribute as username: case on if the attribute exists or not"""
        # get a client that is already authenticated
        client = get_auth_client()

        # trying to get a ticket from a service url matched by a service pattern that use
        # a particular attribute has username. The test user do NOT have this attribute
        response = client.get("/login", {'service': self.service_field_needed_fail})
        # the ticket is not created and a warning is displayed to the user
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"The attribute uid is needed to use that service" in response.content)

        # same but with a attribute that the test user has
        response = client.get("/login", {'service': self.service_field_needed_success})
        # the ticket us created and the user redirected to the service url
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response["Location"].startswith("%s?ticket=" % self.service_field_needed_success)
        )

    @override_settings(CAS_TEST_ATTRIBUTES={'alias': []})
    def test_service_user_field_evaluate_to_false(self):
        """
            Test using a user attribute as username:
            case the attribute exists but evaluate to False
        """
        # get a client that is already authenticated
        client = get_auth_client()
        # trying to get a ticket from a service url matched by a service pattern that use
        # a particular attribute has username. The test user have this attribute, but it is
        # evaluated to False (eg an empty string "" or an empty list [])
        response = client.get("/login", {"service": self.service_field_needed_success})
        # the ticket is not created and a warning is displayed to the user
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"The attribute alias is needed to use that service" in response.content)

    def test_gateway(self):
        """test gateway parameter"""

        # First with an authenticated client that fail to get a ticket for a service
        service = "https://restrict_user_fail.example.com"
        # get a client that is already authenticated
        client = get_auth_client()
        # the authenticated client fail to get a ticket for some reason
        response = client.get("/login", {'service': service, 'gateway': 'on'})
        # as gateway is set, he is redirected to the service url without any ticket
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], service)

        # second for an user not yet authenticated on a valid service
        client = Client()
        # the client fail to get a ticket since he is not yep authenticated
        response = client.get('/login', {'service': service, 'gateway': 'on'})
        # as gateway is set, he is redirected to the service url without any ticket
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], service)

    def test_renew(self):
        """test the authentication renewal request from a service"""
        # use the default test service
        service = "https://www.example.com"
        # get a client that is already authenticated
        client = get_auth_client()
        # ask for a ticket for the service but aks for authentication renewal
        response = client.get("/login", {'service': service, 'renew': 'on'})
        # we are ask to reauthenticate and tell the user why
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"Authentication renewal required by "
                b"service example (https://www.example.com)"
            ) in response.content
        )
        # get the form default parameter
        params = copy_form(response.context["form"])
        # set valid username/password
        params["username"] = settings.CAS_TEST_USER
        params["password"] = settings.CAS_TEST_PASSWORD
        # the renew parameter from the form should be True
        self.assertEqual(params["renew"], True)
        # post the authentication request
        response = client.post("/login", params)
        # the request succed, a ticket is created and we are redirected to the service url
        self.assertEqual(response.status_code, 302)
        ticket_value = response['Location'].split('ticket=')[-1]
        ticket = models.ServiceTicket.objects.get(value=ticket_value)
        # the created ticket is marked has being gottent after a renew. Futher testing about
        # renewing authentication is done in the validate and serviceValidate views tests
        self.assertEqual(ticket.renew, True)

    @override_settings(CAS_SHOW_SERVICE_MESSAGES=False)
    def test_renew_message_disabled(self):
        """test the authentication renewal request from a service"""
        # use the default test service
        service = "https://www.example.com"
        # get a client that is already authenticated
        client = get_auth_client()
        # ask for a ticket for the service but aks for authentication renewal
        response = client.get("/login", {'service': service, 'renew': 'on'})
        # we are ask to reauthenticate and tell the user why
        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            (
                b"Authentication renewal required by "
                b"service example (https://www.example.com)"
            ) in response.content
        )
        # get the form default parameter
        params = copy_form(response.context["form"])
        # set valid username/password
        params["username"] = settings.CAS_TEST_USER
        params["password"] = settings.CAS_TEST_PASSWORD
        # the renew parameter from the form should be True
        self.assertEqual(params["renew"], True)
        # post the authentication request
        response = client.post("/login", params)
        # the request succed, a ticket is created and we are redirected to the service url
        self.assertEqual(response.status_code, 302)
        ticket_value = response['Location'].split('ticket=')[-1]
        ticket = models.ServiceTicket.objects.get(value=ticket_value)
        # the created ticket is marked has being gottent after a renew. Futher testing about
        # renewing authentication is done in the validate and serviceValidate views tests
        self.assertEqual(ticket.renew, True)

    @override_settings(CAS_ENABLE_AJAX_AUTH=True)
    def test_ajax_login_required(self):
        """
            test ajax, login required.
            The ajax methods allow the log a user in using javascript.
            For doing so, every 302 redirection a replaced by a 200 returning a json with the
            url to  redirect to.
            By default, ajax login is disabled.
            If CAS_ENABLE_AJAX_AUTH is True, ajax login is enable and only page on the same domain
            as the CAS can do ajax request. To allow pages on other domains, you need to use CORS.
            You can use the django app corsheaders for that. Be carefull to only allow domains
            you completly trust as any javascript on these domaine will be able to authenticate
            as the user.
        """
        # get a bare client
        client = Client()
        # fetch the login page setting up the custom header HTTP_X_AJAX to tell we wish to de
        # ajax requests
        response = client.get("/login", HTTP_X_AJAX='on')
        # we get a json as response telling us the user need to be authenticated
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["detail"], "login required")
        self.assertEqual(data["url"], "/login")

    @override_settings(CAS_ENABLE_AJAX_AUTH=True)
    def test_ajax_logged_user_deleted(self):
        """test ajax user logged deleted: login required"""
        # get a client that is already authenticated
        client = get_auth_client()
        # delete the user in the db
        user = models.User.objects.get(
            username=settings.CAS_TEST_USER,
            session_key=client.session.session_key
        )
        user.delete()
        # fetch the login page with ajax on
        response = client.get("/login", HTTP_X_AJAX='on')
        # we get a json telling us that the user need to authenticate
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["detail"], "login required")
        self.assertEqual(data["url"], "/login")

    @override_settings(CAS_ENABLE_AJAX_AUTH=True)
    def test_ajax_logged(self):
        """test ajax user is successfully logged"""
        # get a client that is already authenticated
        client = get_auth_client()
        # fetch the login page with ajax on
        response = client.get("/login", HTTP_X_AJAX='on')
        # we get a json telling us that the user is well authenticated
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["detail"], "logged")

    @override_settings(CAS_ENABLE_AJAX_AUTH=True)
    def test_ajax_get_ticket_success(self):
        """test ajax retrieve a ticket for an allowed service"""
        # using the default test service
        service = "https://www.example.com"
        # get a client that is already authenticated
        client = get_auth_client()
        # fetch the login page with ajax on
        response = client.get("/login", {'service': service}, HTTP_X_AJAX='on')
        # we get a json telling us that the ticket has being created
        # and we get the url to fetch to authenticate the user to the service
        # contening the ticket has GET parameter
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["detail"], "auth")
        self.assertTrue(data["url"].startswith('%s?ticket=' % service))

    def test_ajax_get_ticket_success_alt(self):
        """
            test ajax retrieve a ticket for an allowed service.
            Same as above but with CAS_ENABLE_AJAX_AUTH=False
        """
        # using the default test service
        service = "https://www.example.com"
        # get a client that is already authenticated
        client = get_auth_client()
        # fetch the login page with ajax on
        response = client.get("/login", {'service': service}, HTTP_X_AJAX='on')
        # as CAS_ENABLE_AJAX_AUTH is False the ajax request is ignored and word normally:
        # 302 redirect to the service url with ticket as GET parameter. javascript
        # cannot retieve the ticket info and try follow the redirect to an other domain and fail
        # silently
        self.assertEqual(response.status_code, 302)

    @override_settings(CAS_ENABLE_AJAX_AUTH=True)
    def test_ajax_get_ticket_fail(self):
        """test ajax retrieve a ticket for a denied service"""
        # using a denied service url
        service = "https://www.example.org"
        # get a client that is already authenticated
        client = get_auth_client()
        # fetch the login page with ajax on
        response = client.get("/login", {'service': service}, HTTP_X_AJAX='on')
        # we get a json telling us that the service is not allowed
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["detail"], "auth")
        self.assertEqual(data["messages"][0]["level"], "error")
        self.assertEqual(
            data["messages"][0]["message"],
            "Service https://www.example.org not allowed."
        )

    @override_settings(CAS_ENABLE_AJAX_AUTH=True)
    def test_ajax_get_ticket_warn(self):
        """test get a ticket but user asked to be warned"""
        # using the default test service
        service = "https://www.example.com"
        # get a client that is already authenticated wth warn on
        client = get_auth_client(warn="on")
        # fetch the login page with ajax on
        response = client.get("/login", {'service': service}, HTTP_X_AJAX='on')
        # we get a json telling us that we cannot get a ticket transparently and that the
        # user has asked to be warned
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["detail"], "confirmation needed")


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class LogoutTestCase(TestCase):
    """test fot the logout view"""
    def setUp(self):
        """Prepare the test context"""
        # for testing SingleLogOut we need to use a service on localhost were we lanch
        # a simple one request http server
        self.service = 'http://127.0.0.1:45678'
        self.service_pattern = models.ServicePattern.objects.create(
            name="localhost",
            pattern=r"^https?://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
            single_log_out=True
        )
        # return all user attributes
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

    def test_logout(self):
        """logout is idempotent"""
        # get a bare client
        client = Client()

        # call logout
        client.get("/logout")

        # we are still not logged
        self.assertFalse(client.session.get("username"))
        self.assertFalse(client.session.get("authenticated"))

    def test_logout_view(self):
        """test simple logout, logout only an user from one and only one sessions"""
        # get two authenticated client with the same test user (but two different sessions)
        client = get_auth_client()
        client2 = get_auth_client()

        # fetch login, the first client is well authenticated
        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )
        # and session variable are well
        self.assertTrue(client.session["username"] == settings.CAS_TEST_USER)
        self.assertTrue(client.session["authenticated"] is True)

        # call logout with the first client
        response = client.get("/logout")
        # the client is logged out
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"You have successfully logged out from "
                b"the Central Authentication Service"
            ) in response.content
        )
        # and session variable a well cleaned
        self.assertFalse(client.session.get("username"))
        self.assertFalse(client.session.get("authenticated"))
        # client2 is still logged
        self.assertTrue(client2.session["username"] == settings.CAS_TEST_USER)
        self.assertTrue(client2.session["authenticated"] is True)

        response = client.get("/login")
        # fetch login, the second client is well authenticated
        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )

    def test_logout_from_all_session(self):
        """test logout from all my session"""
        # get two authenticated client with the same test user (but two different sessions)
        client = get_auth_client()
        client2 = get_auth_client()

        # call logout with the first client and ask to be logged out from all of this user sessions
        client.get("/logout?all=1")

        # both client are logged out
        self.assertFalse(client.session.get("username"))
        self.assertFalse(client.session.get("authenticated"))
        self.assertFalse(client2.session.get("username"))
        self.assertFalse(client2.session.get("authenticated"))

    def assert_redirect_to_service(self, client, response):
        """assert logout redirect to parameter"""
        # assert a redirection with a service
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.has_header("Location"))
        self.assertEqual(response["Location"], "https://www.example.com")

        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        # assert we are not longer logged in
        self.assertFalse(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )

    def test_logout_view_url(self):
        """test logout redirect to url parameter"""
        # get a client that is authenticated
        client = get_auth_client()

        # logout with an url paramer
        response = client.get('/logout?url=https://www.example.com')
        # we are redirected to the addresse of the url parameter
        self.assert_redirect_to_service(client, response)

    def test_logout_view_service(self):
        """test logout redirect to service parameter"""
        # get a client that is authenticated
        client = get_auth_client()

        # logout with a service parameter
        response = client.get('/logout?service=https://www.example.com')
        # we are redirected to the addresse of the service parameter
        self.assert_redirect_to_service(client, response)

    def test_logout_slo(self):
        """test logout from a service with SLO support"""
        parameters = []

        # test normal SLO
        # setup a simple one request http server
        (httpd, host, port) = HttpParamsHandler.run()[0:3]
        # build a service url depending on which port the http server has binded
        service = "http://%s:%s" % (host, port)
        # get a ticket requested by client and being validated by the service
        (client, ticket) = get_validated_ticket(service)[:2]
        # the client logout triggering the send of the SLO requests
        client.get('/logout')
        # we store the POST parameters send for this ticket for furthur analisys
        parameters.append((httpd.PARAMS, ticket))

        # text SLO with a single_log_out_callback
        # setup a simple one request http server
        (httpd, host, port) = HttpParamsHandler.run()[0:3]
        # set the default test service pattern to use the http server port for SLO requests.
        # in fact, this single_log_out_callback parametter is usefull to implement SLO
        # for non http service like imap or ftp
        self.service_pattern.single_log_out_callback = "http://%s:%s" % (host, port)
        self.service_pattern.save()
        # get a ticket requested by client and being validated by the service
        (client, ticket) = get_validated_ticket(self.service)[:2]
        # the client logout triggering the send of the SLO requests
        client.get('/logout')
        # we store the POST parameters send for this ticket for furthur analisys
        parameters.append((httpd.PARAMS, ticket))

        # for earch POST parameters and corresponding ticket
        for (params, ticket) in parameters:
            # there is a POST parameter 'logoutRequest'
            self.assertTrue(b'logoutRequest' in params and params[b'logoutRequest'])

            # it is a valid xml
            root = etree.fromstring(params[b'logoutRequest'][0])
            # contening a <samlp:LogoutRequest> tag
            self.assertTrue(
                root.xpath(
                    "//samlp:LogoutRequest",
                    namespaces={"samlp": "urn:oasis:names:tc:SAML:2.0:protocol"}
                )
            )
            # with a tag <samlp:SessionIndex> enclosing the value of the ticket
            session_index = root.xpath(
                "//samlp:SessionIndex",
                namespaces={"samlp": "urn:oasis:names:tc:SAML:2.0:protocol"}
            )
            self.assertEqual(len(session_index), 1)
            self.assertEqual(session_index[0].text, ticket.value)

        # SLO error are displayed on logout page
        (client, ticket) = get_validated_ticket(self.service)[:2]
        # the client logout triggering the send of the SLO requests but
        # not http server are listening
        response = client.get('/logout')
        self.assertTrue(b"Error during service logout" in response.content)

    @override_settings(CAS_ENABLE_AJAX_AUTH=True)
    def test_ajax_logout(self):
        """
            test ajax logout. These methods are here, but I do not really see an use case for
            javascript logout
        """
        # get a client that is authenticated
        client = get_auth_client()

        # fetch the logout page with ajax on
        response = client.get('/logout', HTTP_X_AJAX='on')
        # we get a json telling us the user is well logged out
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["detail"], "logout")
        self.assertEqual(data['session_nb'], 1)

    @override_settings(CAS_ENABLE_AJAX_AUTH=True)
    def test_ajax_logout_all_session(self):
        """test ajax logout from a random number a sessions"""
        # fire a random int in [2, 10[
        nb_client = random.randint(2, 10)
        # get this much of logged clients all for the test user
        clients = [get_auth_client() for i in range(nb_client)]
        # fetch the logout page with ajax on, requesting to logout from all sessions
        response = clients[0].get('/logout?all=1', HTTP_X_AJAX='on')
        # we get a json telling us the user is well logged out and the number of session
        # the user has being logged out
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["detail"], "logout")
        self.assertEqual(data['session_nb'], nb_client)

    @override_settings(CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT=True)
    def test_redirect_after_logout(self):
        """Test redirect to login after logout parameter"""
        # get a client that is authenticated
        client = get_auth_client()

        # fetch the logout page
        response = client.get('/logout')
        # as CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT is True, we are redirected to the login page
        self.assertEqual(response.status_code, 302)
        if django.VERSION < (1, 9):  # pragma: no cover coverage is computed with dango 1.9
            self.assertEqual(response["Location"], "http://testserver/login")
        else:
            self.assertEqual(response["Location"], "/login")
        self.assertFalse(client.session.get("username"))
        self.assertFalse(client.session.get("authenticated"))

    @override_settings(CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT=True)
    def test_redirect_after_logout_to_service(self):
        """test prevalence of redirect url/service parameter over redirect to login after logout"""
        # get a client that is authenticated
        client = get_auth_client()

        # fetch the logout page with an url parameter
        response = client.get('/logout?url=https://www.example.com')
        # we are redirected to the url parameter and not to the login page
        self.assert_redirect_to_service(client, response)

        # fetch the logout page with an service parameter
        response = client.get('/logout?service=https://www.example.com')
        # we are redirected to the service parameter and not to the login page
        self.assert_redirect_to_service(client, response)

    @override_settings(CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT=True, CAS_ENABLE_AJAX_AUTH=True)
    def test_ajax_redirect_after_logout(self):
        """Test ajax redirect to login after logout parameter"""
        # get a client that is authenticated
        client = get_auth_client()

        # fetch the logout page with ajax on
        response = client.get('/logout', HTTP_X_AJAX='on')
        # we get a json telling us the user is well logged out. And url key is added to aks for
        # redirection to the login page
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["detail"], "logout")
        self.assertEqual(data['session_nb'], 1)
        self.assertEqual(data['url'], '/login')


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class AuthTestCase(TestCase):
    """
        Test for the auth view, used for external services
        to validate (user, pass, service) tuples.
    """
    def setUp(self):
        """preparing test context"""
        # setting up a default test service url and pattern
        self.service = 'https://www.example.com'
        models.ServicePattern.objects.create(
            name="example",
            pattern=r"^https://www\.example\.com(/.*)?$"
        )

    @override_settings(CAS_AUTH_SHARED_SECRET='test')
    def test_auth_view_goodpass(self):
        """successful request are awsered by yes"""
        # get a bare client
        client = Client()
        # post the the auth view a valid (username, password, service) and the shared secret
        # to test the user again the service, a user is created in the database for the
        # current session and is then deleted as the user is not authenticated
        response = client.post(
            '/auth',
            {
                'username': settings.CAS_TEST_USER,
                'password': settings.CAS_TEST_PASSWORD,
                'service': self.service,
                'secret': 'test'
            }
        )
        # as (username, password, service) and the hared secret are valid, we get yes as a response
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'yes\n')

    @override_settings(CAS_AUTH_SHARED_SECRET='test')
    def test_auth_view_goodpass_logged(self):
        """successful request are awsered by yes, using a logged sessions"""
        # same as above
        client = get_auth_client()
        # to test the user again the service, a user is fetch in the database for the
        # current session and is NOT deleted as the user is currently logged.
        # Deleting the user from the database would cause the user to be logged out as
        # showed in the login tests
        response = client.post(
            '/auth',
            {
                'username': settings.CAS_TEST_USER,
                'password': settings.CAS_TEST_PASSWORD,
                'service': self.service,
                'secret': 'test'
            }
        )
        # as (username, password, service) and the hared secret are valid, we get yes as a response
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'yes\n')

    @override_settings(CAS_AUTH_SHARED_SECRET='test')
    def test_auth_view_badpass(self):
        """ bag user password => no"""
        client = Client()
        response = client.post(
            '/auth',
            {
                'username': settings.CAS_TEST_USER,
                'password': 'badpass',
                'service': self.service,
                'secret': 'test'
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'no\n')

    @override_settings(CAS_AUTH_SHARED_SECRET='test')
    def test_auth_view_badservice(self):
        """bad service => no"""
        client = Client()
        response = client.post(
            '/auth',
            {
                'username': settings.CAS_TEST_USER,
                'password': settings.CAS_TEST_PASSWORD,
                'service': 'https://www.example.org',
                'secret': 'test'
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'no\n')

    @override_settings(CAS_AUTH_SHARED_SECRET='test')
    def test_auth_view_badsecret(self):
        """bad api key => no"""
        client = Client()
        response = client.post(
            '/auth',
            {
                'username': settings.CAS_TEST_USER,
                'password': settings.CAS_TEST_PASSWORD,
                'service': self.service,
                'secret': 'badsecret'
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'no\n')

    def test_auth_view_badsettings(self):
        """api not set => error"""
        client = Client()
        response = client.post(
            '/auth',
            {
                'username': settings.CAS_TEST_USER,
                'password': settings.CAS_TEST_PASSWORD,
                'service': self.service,
                'secret': 'test'
            }
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"no\nplease set CAS_AUTH_SHARED_SECRET")

    @override_settings(CAS_AUTH_SHARED_SECRET='test')
    def test_auth_view_missing_parameter(self):
        """missing parameter in request => no"""
        client = Client()
        params = {
            'username': settings.CAS_TEST_USER,
            'password': settings.CAS_TEST_PASSWORD,
            'service': self.service,
            'secret': 'test'
        }
        for key in ['username', 'password', 'service']:
            send_params = params.copy()
            del send_params[key]
            response = client.post('/auth', send_params)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b'no\n')


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class ValidateTestCase(TestCase):
    """tests for the validate view"""
    def setUp(self):
        """preparing test context"""
        # setting up a default test service url and pattern
        self.service = 'https://www.example.com'
        self.service_pattern = models.ServicePattern.objects.create(
            name="example",
            pattern=r"^https://www\.example\.com(/.*)?$"
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)
        # setting up a test service and pattern using a multi valued user attribut as username
        # the first value of the list should be used as username
        self.service_user_field = "https://user_field.example.com"
        self.service_pattern_user_field = models.ServicePattern.objects.create(
            name="user field",
            pattern=r"^https://user_field\.example\.com(/.*)?$",
            user_field="alias"
        )
        # setting up a test service and pattern using a single valued user attribut as username
        self.service_user_field_alt = "https://user_field_alt.example.com"
        self.service_pattern_user_field_alt = models.ServicePattern.objects.create(
            name="user field alt",
            pattern=r"^https://user_field_alt\.example\.com(/.*)?$",
            user_field="nom"
        )

    def test_validate_view_ok(self):
        """test for a valid (ticket, service)"""
        # get a ticket waiting to be validated for self.service
        ticket = get_user_ticket_request(self.service)[1]

        # get a bare client
        client = Client()
        # calling the validate view with this ticket value and service
        response = client.get('/validate', {'ticket': ticket.value, 'service': self.service})
        # get yes as a response and the test user username
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'yes\ntest\n')

    def test_validate_service_renew(self):
        """test with a valid (ticket, service) asking for auth renewal"""
        # case 1 client is renewing and service ask for renew
        response = get_auth_client(renew="True", service=self.service)[1]
        self.assertEqual(response.status_code, 302)
        ticket_value = response['Location'].split('ticket=')[-1]
        # get a bare client
        client = Client()
        # requesting validation with a good (ticket, service)
        response = client.get(
            '/validate',
            {'ticket': ticket_value, 'service': self.service, 'renew': 'True'}
        )
        # the validation should succes with username settings.CAS_TEST_USER and transmit
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'yes\ntest\n')

        # cas2 client is renewing and service do not ask for renew
        (client2, response) = get_auth_client(renew="True", service=self.service)
        self.assertEqual(response.status_code, 302)
        ticket_value = response['Location'].split('ticket=')[-1]
        # get a bare client
        client = Client()
        # requesting validation with a good (ticket, service)
        response = client.get(
            '/validate',
            {'ticket': ticket_value, 'service': self.service}
        )
        # the validation should succes with username settings.CAS_TEST_USER and transmit
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'yes\ntest\n')

        # case 3, client is not renewing and service ask for renew (client is authenticated)
        response = client2.get("/login", {"service": self.service})
        self.assertEqual(response.status_code, 302)
        ticket_value = response['Location'].split('ticket=')[-1]
        client = Client()
        # requesting validation with a good (ticket, service)
        response = client.get(
            '/validate',
            {'ticket': ticket_value, 'service': self.service, 'renew': 'True'}
        )
        # the validation should fail
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'no\n')

    def test_validate_view_badservice(self):
        """test for a valid ticket but bad service"""
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        # calling the validate view with this ticket value and another service
        response = client.get(
            '/validate',
            {'ticket': ticket.value, 'service': "https://www.example.org"}
        )
        # the ticket service and validation service do not match, validation should fail
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'no\n')

    def test_validate_view_badticket(self):
        """test for a bad ticket but valid service"""
        get_user_ticket_request(self.service)

        client = Client()
        # calling the validate view with another ticket value and this service
        response = client.get(
            '/validate',
            {'ticket': "%s-RANDOM" % settings.CAS_SERVICE_TICKET_PREFIX, 'service': self.service}
        )
        # as the ticket is bad, validation should fail
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'no\n')

    def test_validate_user_field_ok(self):
        """
            test with a good user_field. A bad user_field (that evaluate to False)
            wont happed cause it is filtered in the login view
        """
        for (service, username) in [
            (self.service_user_field, b"demo1"),
            (self.service_user_field_alt, b"Nymous")
        ]:
            ticket = get_user_ticket_request(service)[1]
            client = Client()
            response = client.get(
                '/validate',
                {'ticket': ticket.value, 'service': service}
            )
            self.assertEqual(response.status_code, 200)
            # the user attribute is well used as username
            self.assertEqual(response.content, b'yes\n' + username + b'\n')

    def test_validate_missing_parameter(self):
        """test with a missing GET parameter among [service, ticket]"""
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        params = {'ticket': ticket.value, 'service': self.service}
        for key in ['ticket', 'service']:
            send_params = params.copy()
            del send_params[key]
            response = client.get('/validate', send_params)
            # if the GET request is missing the ticket or
            # service GET parameter, validation should fail
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b'no\n')


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class ValidateServiceTestCase(TestCase, XmlContent):
    """tests for the serviceValidate view"""
    def setUp(self):
        """preparing test context"""
        # for testing SingleLogOut and Proxy GrantingTicket transmission
        # we need to use a service on localhost were we launch
        # a simple one request http server
        self.service = 'http://127.0.0.1:45678'
        self.service_pattern = models.ServicePattern.objects.create(
            name="localhost",
            pattern=r"^https?://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
            # allow to request PGT by the service
            proxy_callback=True,
            # allow to request PT for the service
            proxy=True
        )
        # tell the service pattern to transmit all the user attributes (* is a joker)
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

        # test service pattern using the attribute alias as username
        self.service_user_field = "https://user_field.example.com"
        self.service_pattern_user_field = models.ServicePattern.objects.create(
            name="user field",
            pattern=r"^https://user_field\.example\.com(/.*)?$",
            user_field="alias"
        )
        # test service pattern using the attribute nom as username
        self.service_user_field_alt = "https://user_field_alt.example.com"
        self.service_pattern_user_field_alt = models.ServicePattern.objects.create(
            name="user field alt",
            pattern=r"^https://user_field_alt\.example\.com(/.*)?$",
            user_field="nom"
        )

        # test service pattern only transmiting one single attributes
        self.service_one_attribute = "https://one_attribute.example.com"
        self.service_pattern_one_attribute = models.ServicePattern.objects.create(
            name="one_attribute",
            pattern=r"^https://one_attribute\.example\.com(/.*)?$"
        )
        models.ReplaceAttributName.objects.create(
            name="nom",
            service_pattern=self.service_pattern_one_attribute
        )

        # test service pattern testing attribute name and value replacement
        self.service_replace_attribute_list = "https://replace_attribute_list.example.com"
        self.service_pattern_replace_attribute_list = models.ServicePattern.objects.create(
            name="replace_attribute_list",
            pattern=r"^https://replace_attribute_list\.example\.com(/.*)?$",
        )
        models.ReplaceAttributValue.objects.create(
            attribut="alias",
            pattern="^demo",
            replace="truc",
            service_pattern=self.service_pattern_replace_attribute_list
        )
        models.ReplaceAttributName.objects.create(
            name="alias",
            replace="ALIAS",
            service_pattern=self.service_pattern_replace_attribute_list
        )
        self.service_replace_attribute = "https://replace_attribute.example.com"
        self.service_pattern_replace_attribute = models.ServicePattern.objects.create(
            name="replace_attribute",
            pattern=r"^https://replace_attribute\.example\.com(/.*)?$",
        )
        models.ReplaceAttributValue.objects.create(
            attribut="nom",
            pattern="N",
            replace="P",
            service_pattern=self.service_pattern_replace_attribute
        )
        models.ReplaceAttributName.objects.create(
            name="nom",
            replace="NOM",
            service_pattern=self.service_pattern_replace_attribute
        )

    def test_validate_service_view_ok(self):
        """test with a valid (ticket, service), the username and all attributes are transmited"""
        # get a ticket from an authenticated user waiting for validation
        ticket = get_user_ticket_request(self.service)[1]

        # get a bare client
        client = Client()
        # requesting validation with a good (ticket, service)
        response = client.get('/serviceValidate', {'ticket': ticket.value, 'service': self.service})
        # the validation should succes with username settings.CAS_TEST_USER and transmit
        # the attributes settings.CAS_TEST_ATTRIBUTES
        self.assert_success(response, settings.CAS_TEST_USER, settings.CAS_TEST_ATTRIBUTES)

    def test_validate_proxy(self):
        """test ProxyTicket validation on /proxyValidate and /serviceValidate"""
        ticket = get_proxy_ticket(self.service)
        client = Client()
        # requesting validation with a good (ticket, service)
        response = client.get('/proxyValidate', {'ticket': ticket.value, 'service': self.service})
        # and it should succeed
        self.assert_success(response, settings.CAS_TEST_USER, settings.CAS_TEST_ATTRIBUTES)

        ticket = get_proxy_ticket(self.service)
        client = Client()
        # requesting validation with a good (ticket, service)
        response = client.get('/serviceValidate', {'ticket': ticket.value, 'service': self.service})
        # and it should succeed
        self.assert_error(
            response,
            "INVALID_TICKET",
            ticket.value
        )

    def test_validate_service_renew(self):
        """test with a valid (ticket, service) asking for auth renewal"""
        # case 1 client is renewing and service ask for renew
        response = get_auth_client(renew="True", service=self.service)[1]
        self.assertEqual(response.status_code, 302)
        ticket_value = response['Location'].split('ticket=')[-1]
        # get a bare client
        client = Client()
        # requesting validation with a good (ticket, service)
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket_value, 'service': self.service, 'renew': 'True'}
        )
        # the validation should succes with username settings.CAS_TEST_USER and transmit
        # the attributes settings.CAS_TEST_ATTRIBUTES
        self.assert_success(response, settings.CAS_TEST_USER, settings.CAS_TEST_ATTRIBUTES)

        # cas2 client is renewing and service do not ask for renew
        (client2, response) = get_auth_client(renew="True", service=self.service)
        self.assertEqual(response.status_code, 302)
        ticket_value = response['Location'].split('ticket=')[-1]
        # get a bare client
        client = Client()
        # requesting validation with a good (ticket, service)
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket_value, 'service': self.service}
        )
        # the validation should succes with username settings.CAS_TEST_USER and transmit
        # the attributes settings.CAS_TEST_ATTRIBUTES
        self.assert_success(response, settings.CAS_TEST_USER, settings.CAS_TEST_ATTRIBUTES)

        # case 3, client is not renewing and service ask for renew (client is authenticated)
        response = client2.get("/login", {"service": self.service})
        self.assertEqual(response.status_code, 302)
        ticket_value = response['Location'].split('ticket=')[-1]
        client = Client()
        # requesting validation with a good (ticket, service)
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket_value, 'service': self.service, 'renew': 'True'}
        )
        # the validation should fail
        self.assert_error(
            response,
            "INVALID_TICKET",
            'ticket not found'
        )

    def test_validate_service_view_ok_one_attribute(self):
        """
            test with a valid (ticket, service), the username and
            the 'nom' only attribute are transmited
        """
        # get a ticket for a service that transmit only one attribute
        ticket = get_user_ticket_request(self.service_one_attribute)[1]

        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': self.service_one_attribute}
        )
        # the validation should succed, returning settings.CAS_TEST_USER as username and a single
        # attribute 'nom'
        self.assert_success(
            response,
            settings.CAS_TEST_USER,
            {'nom': settings.CAS_TEST_ATTRIBUTES['nom']}
        )

    def test_validate_replace_attributes(self):
        """test with a valid (ticket, service), attributes name and value replacement"""
        # get a ticket for a service pattern replacing attributes names
        # nom -> NOM and value nom -> s/^N/P/ for a single valued attribute
        ticket = get_user_ticket_request(self.service_replace_attribute)[1]
        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': self.service_replace_attribute}
        )
        self.assert_success(
            response,
            settings.CAS_TEST_USER,
            {'NOM': 'Pymous'}
        )

        # get a ticket for a service pattern replacing attributes names
        # alias -> ALIAS and value alias -> s/demo/truc/ for a multi valued attribute
        ticket = get_user_ticket_request(self.service_replace_attribute_list)[1]
        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': self.service_replace_attribute_list}
        )
        self.assert_success(
            response,
            settings.CAS_TEST_USER,
            {'ALIAS': ['truc1', 'truc2']}
        )

    def test_validate_service_view_badservice(self):
        """test with a valid ticket but a bad service, the validatin should fail"""
        # get a ticket for service A
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        bad_service = "https://www.example.org"
        # try to validate it for service B
        response = client.get('/serviceValidate', {'ticket': ticket.value, 'service': bad_service})
        # the validation should fail with error code "INVALID_SERVICE"
        self.assert_error(
            response,
            "INVALID_SERVICE",
            bad_service
        )

    def test_validate_service_view_badticket_goodprefix(self):
        """
            test with a good service but a bad ticket begining with ST-,
            the validation should fail with the error (INVALID_TICKET, ticket not found)
        """
        get_user_ticket_request(self.service)

        client = Client()
        bad_ticket = "%s-RANDOM" % settings.CAS_SERVICE_TICKET_PREFIX
        response = client.get('/serviceValidate', {'ticket': bad_ticket, 'service': self.service})
        self.assert_error(
            response,
            "INVALID_TICKET",
            'ticket not found'
        )

    def test_validate_service_view_badticket_badprefix(self):
        """
            test with a good service bud a bad ticket not begining with ST-,
            the validation should fail with the error (INVALID_TICKET, `the ticket`)
        """
        get_user_ticket_request(self.service)

        client = Client()
        bad_ticket = "RANDOM"
        response = client.get('/serviceValidate', {'ticket': bad_ticket, 'service': self.service})
        self.assert_error(
            response,
            "INVALID_TICKET",
            bad_ticket
        )

    def test_validate_service_view_ok_pgturl(self):
        """test the retrieval of a ProxyGrantingTicket"""
        # start a simple on request http server
        (httpd, host, port) = HttpParamsHandler.run()[0:3]
        # construct the service from it
        service = "http://%s:%s" % (host, port)

        # get a ticket to be validated
        ticket = get_user_ticket_request(service)[1]

        client = Client()
        # request a PGT ticket then validating the ticket by setting the pgtUrl parameter
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': service, 'pgtUrl': service}
        )
        # We should have recieved the PGT via a GET request parameter on the simple http server
        pgt_params = httpd.PARAMS
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        # the validation response should return a id to match again the request transmitting the PGT
        pgtiou = root.xpath(
            "//cas:proxyGrantingTicket",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(pgtiou), 1)
        # the matching id for making corresponde one PGT to a validatin response should match
        self.assertEqual(pgt_params["pgtIou"], pgtiou[0].text)
        # the PGT is present in the receive GET requests parameters
        self.assertTrue("pgtId" in pgt_params)

    def test_validate_service_pgturl_sslerror(self):
        """test the retrieval of a ProxyGrantingTicket with a SSL error on the pgtUrl"""
        (host, port) = HttpParamsHandler.run()[1:3]
        # is fact the service listen on http and not https raisin a SSL Protocol Error
        # but other SSL/TLS error should behave the same
        service = "https://%s:%s" % (host, port)

        ticket = get_user_ticket_request(service)[1]

        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': service, 'pgtUrl': service}
        )
        # The pgtUrl is validated: it must be localhost or have valid x509 certificat and
        # certificat validation should succed. Moreother, pgtUrl should match a service pattern
        # with proxy_callback set to True
        self.assert_error(
            response,
            "INVALID_PROXY_CALLBACK",
        )

    def test_validate_service_pgturl_404(self):
        """
            test the retrieval on a ProxyGrantingTicket then to pgtUrl return a http error.
            PGT creation should be aborted but the ticket still be valid
        """
        (host, port) = Http404Handler.run()[1:3]
        service = "http://%s:%s" % (host, port)

        ticket = get_user_ticket_request(service)[1]
        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': service, 'pgtUrl': service}
        )
        # The ticket is successfully validated
        root = self.assert_success(response, settings.CAS_TEST_USER, settings.CAS_TEST_ATTRIBUTES)
        # but no PGT is transmitted
        pgtiou = root.xpath(
            "//cas:proxyGrantingTicket",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertFalse(pgtiou)

    def test_validate_service_pgturl_bad_proxy_callback(self):
        """test the retrieval of a ProxyGrantingTicket, not allowed pgtUrl should be denied"""
        self.service_pattern.proxy_callback = False
        self.service_pattern.save()
        ticket = get_user_ticket_request(self.service)[1]
        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': self.service, 'pgtUrl': self.service}
        )
        self.assert_error(
            response,
            "INVALID_PROXY_CALLBACK",
            "callback url not allowed by configuration"
        )

        self.service_pattern.proxy_callback = True

        ticket = get_user_ticket_request(self.service)[1]
        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': self.service, 'pgtUrl': "https://www.example.org"}
        )
        self.assert_error(
            response,
            "INVALID_PROXY_CALLBACK",
            "callback url not allowed by configuration"
        )

    def test_validate_user_field_ok(self):
        """
            test with a good user_field. A bad user_field (that evaluate to False)
            wont happed cause it is filtered in the login view
        """
        for (service, username) in [
            (self.service_user_field, settings.CAS_TEST_ATTRIBUTES["alias"][0]),
            (self.service_user_field_alt, settings.CAS_TEST_ATTRIBUTES["nom"])
        ]:
            # requesting a ticket for a service url matched by a service pattern using a user
            # attribute as username
            ticket = get_user_ticket_request(service)[1]
            client = Client()
            response = client.get(
                '/serviceValidate',
                {'ticket': ticket.value, 'service': service}
            )
            # The validate shoudl be successful with specified username and no attributes transmited
            self.assert_success(
                response,
                username,
                {}
            )

    def test_validate_missing_parameter(self):
        """test with a missing GET parameter among [service, ticket]"""
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        params = {'ticket': ticket.value, 'service': self.service}
        for key in ['ticket', 'service']:
            send_params = params.copy()
            del send_params[key]
            response = client.get('/serviceValidate', send_params)
            # a validation request with a missing GET parameter should fail
            self.assert_error(
                response,
                "INVALID_REQUEST",
                "you must specify a service and a ticket"
            )


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class ProxyTestCase(TestCase, BaseServicePattern, XmlContent):
    """tests for the proxy view"""
    def setUp(self):
        """preparing test context"""
        # we prepare a bunch a service url and service patterns for tests
        self.setup_service_patterns(proxy=True)

        # set the default service pattern to localhost to be able to retrieve PGT
        self.service = 'http://127.0.0.1'
        self.service_pattern = models.ServicePattern.objects.create(
            name="localhost",
            pattern=r"^http://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
            proxy=True,
            proxy_callback=True
        )
        # transmit all attributes
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

    def test_validate_proxy_ok(self):
        """
            Get a PGT, get a proxy ticket, validate it. Validation should succeed and
            show the proxy service URL.
        """
        # we directrly get a ProxyGrantingTicket
        params = get_pgt()

        # We try get a proxy ticket with our PGT
        client1 = Client()
        # for what we send a GET request to /proxy with ge PGT and the target service for which
        # we want a ProxyTicket to.
        response = client1.get(
            '/proxy',
            {'pgt': params['pgtId'], 'targetService': "https://www.example.com"}
        )
        self.assertEqual(response.status_code, 200)

        # we should sucessfully reteive a PT
        root = etree.fromstring(response.content)
        sucess = root.xpath("//cas:proxySuccess", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertTrue(sucess)

        proxy_ticket = root.xpath(
            "//cas:proxyTicket",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(proxy_ticket), 1)
        proxy_ticket = proxy_ticket[0].text

        # validate the proxy ticket with the service for which is was emitted
        client2 = Client()
        response = client2.get(
            '/proxyValidate',
            {'ticket': proxy_ticket, 'service': "https://www.example.com"}
        )
        # validation should succeed and return settings.CAS_TEST_USER as username
        # and settings.CAS_TEST_ATTRIBUTES as attributes
        root = self.assert_success(
            response,
            settings.CAS_TEST_USER,
            settings.CAS_TEST_ATTRIBUTES
        )

        # in the PT validation response, it should have the service url of the PGY
        proxies = root.xpath("//cas:proxies", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(proxies), 1)
        proxy = proxies[0].xpath("//cas:proxy", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(proxy), 1)
        self.assertEqual(proxy[0].text, params["service"])

    def test_validate_proxy_bad_pgt(self):
        """Try to get a ProxyTicket with a bad PGT. The PT generation should fail"""
        # we directrly get a ProxyGrantingTicket
        params = get_pgt()
        client = Client()
        response = client.get(
            '/proxy',
            {
                'pgt': "%s-RANDOM" % settings.CAS_PROXY_GRANTING_TICKET_PREFIX,
                'targetService': params['service']
            }
        )
        self.assert_error(
            response,
            "INVALID_TICKET",
            "PGT %s-RANDOM not found" % settings.CAS_PROXY_GRANTING_TICKET_PREFIX
        )

    def test_validate_proxy_bad_service(self):
        """
            Try to get a ProxyTicket for a denied service and
            a service that do not allow PT. The PT generation should fail.
        """
        # we directrly get a ProxyGrantingTicket
        params = get_pgt()

        # try to get a PT for a denied service
        client1 = Client()
        response = client1.get(
            '/proxy',
            {'pgt': params['pgtId'], 'targetService': "https://www.example.org"}
        )
        self.assert_error(
            response,
            "UNAUTHORIZED_SERVICE",
            "https://www.example.org"
        )

        # try to get a PT for a service that do not allow PT
        self.service_pattern.proxy = False
        self.service_pattern.save()

        client2 = Client()
        response = client2.get(
            '/proxy',
            {'pgt': params['pgtId'], 'targetService': params['service']}
        )

        self.assert_error(
            response,
            "UNAUTHORIZED_SERVICE",
            'the service %s does not allow proxy tickets' % params['service']
        )

        self.service_pattern.proxy = True
        self.service_pattern.save()

    def test_proxy_unauthorized_user(self):
        """
            Try to get a PT for services that do not allow the current user:
                * first with a service that restrict allowed username
                * second with a service requiring somes conditions on the user attributes
                * third with a service using a particular user attribute as username
            All this tests should fail
        """
        # we directrly get a ProxyGrantingTicket
        params = get_pgt()

        for service in [
            # do ot allow the test username
            self.service_restrict_user_fail,
            # require the 'nom' attribute to be 'toto'
            self.service_filter_fail,
            #  want to use the non-exitant 'uid' attribute as username
            self.service_field_needed_fail
        ]:
            client = Client()
            response = client.get(
                '/proxy',
                {'pgt': params['pgtId'], 'targetService': service}
            )
            # PT generation should fail
            self.assert_error(
                response,
                "UNAUTHORIZED_USER",
                'User %s not allowed on %s' % (settings.CAS_TEST_USER, service)
            )

    def test_proxy_missing_parameter(self):
        """Try to get a PGT with some missing GET parameters. The PT should not be emited"""
        params = get_pgt()
        base_params = {'pgt': params['pgtId'], 'targetService': "https://www.example.org"}
        for key in ["pgt", 'targetService']:
            send_params = base_params.copy()
            del send_params[key]
            client = Client()
            response = client.get("/proxy", send_params)
            self.assert_error(
                response,
                "INVALID_REQUEST",
                'you must specify and pgt and targetService'
            )


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class SamlValidateTestCase(TestCase, BaseServicePattern, XmlContent):
    """tests for the proxy view"""
    def setUp(self):
        """preparing test context"""
        # we prepare a bunch a service url and service patterns for tests
        self.setup_service_patterns(proxy=True)

        # special service pattern for retrieving a PGT
        self.service_pgt = 'http://127.0.0.1'
        self.service_pattern_pgt = models.ServicePattern.objects.create(
            name="localhost",
            pattern=r"^http://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
            proxy=True,
            proxy_callback=True
        )
        models.ReplaceAttributName.objects.create(
            name="*",
            service_pattern=self.service_pattern_pgt
        )

    # template for the XML POST need to be send to validate a ticket using SAML 1.1
    xml_template = """
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <samlp:Request
            xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"
            MajorVersion="1" MinorVersion="1"
            RequestID="%(request_id)s"
            IssueInstant="%(issue_instant)s"
        >
            <samlp:AssertionArtifact>%(ticket)s</samlp:AssertionArtifact>
        </samlp:Request>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

    def assert_success(self, response, username, original_attributes):
        """assert ticket validation success"""
        self.assertEqual(response.status_code, 200)
        # on validation success, the response should have a StatusCode set to Success
        root = etree.fromstring(response.content)
        success = root.xpath(
            "//samlp:StatusCode",
            namespaces={'samlp': "urn:oasis:names:tc:SAML:1.0:protocol"}
        )
        self.assertEqual(len(success), 1)
        self.assertTrue(success[0].attrib['Value'].endswith(":Success"))

        # the user username should be return whithin <NameIdentifier> tags
        user = root.xpath(
            "//samla:NameIdentifier",
            namespaces={'samla': "urn:oasis:names:tc:SAML:1.0:assertion"}
        )
        self.assertTrue(user)
        self.assertEqual(user[0].text, username)

        # the returned attributes should match original_attributes
        attributes = root.xpath(
            "//samla:AttributeStatement/samla:Attribute",
            namespaces={'samla': "urn:oasis:names:tc:SAML:1.0:assertion"}
        )
        ignore_attrs = {
            "authenticationDate", "longTermAuthenticationRequestTokenUsed", "isFromNewLogin"
        } - set(original_attributes.keys())
        attrs = set()
        for attr in attributes:
            if not attr.attrib['AttributeName'] in ignore_attrs:
                attrs.add((attr.attrib['AttributeName'], attr.getchildren()[0].text))
        original = set()
        for key, value in original_attributes.items():
            if isinstance(value, list):
                for subval in value:
                    original.add((key, subval))
            else:
                original.add((key, value))
        self.assertEqual(original, attrs)

    def assert_error(self, response, code, msg=None):
        """assert ticket validation error"""
        self.assertEqual(response.status_code, 200)
        # on error the status code value should be the one provider in `code`
        root = etree.fromstring(response.content)
        error = root.xpath(
            "//samlp:StatusCode",
            namespaces={'samlp': "urn:oasis:names:tc:SAML:1.0:protocol"}
        )
        self.assertEqual(len(error), 1)
        self.assertTrue(error[0].attrib['Value'].endswith(":%s" % code))
        # it may have an error message
        if msg is not None:
            self.assertEqual(error[0].text, msg)

    def test_saml_ok(self):
        """
            test with a valid (ticket, service), with a ST and a PT,
            the username and all attributes are transmited"""
        tickets = [
            # return a ServiceTicket (standard ticket) waiting for validation
            get_user_ticket_request(self.service)[1],
            # return a PT waiting for validation
            get_proxy_ticket(self.service)
        ]

        for ticket in tickets:
            client = Client()
            # we send the POST validation requests
            response = client.post(
                '/samlValidate?TARGET=%s' % self.service,
                self.xml_template % {
                    'ticket': ticket.value,
                    'request_id': utils.gen_saml_id(),
                    'issue_instant': timezone.now().isoformat()
                },
                content_type="text/xml; encoding='utf-8'"
            )
            # and it should succeed
            self.assert_success(response, settings.CAS_TEST_USER, settings.CAS_TEST_ATTRIBUTES)

    def test_saml_ok_user_field(self):
        """test with a valid(ticket, service), use a attributes as transmitted username"""
        for (service, username) in [
            (self.service_field_needed_success, settings.CAS_TEST_ATTRIBUTES['alias'][0]),
            (self.service_field_needed_success_alt, settings.CAS_TEST_ATTRIBUTES['nom'])
        ]:
            ticket = get_user_ticket_request(service)[1]

            client = Client()
            response = client.post(
                '/samlValidate?TARGET=%s' % service,
                self.xml_template % {
                    'ticket': ticket.value,
                    'request_id': utils.gen_saml_id(),
                    'issue_instant': timezone.now().isoformat()
                },
                content_type="text/xml; encoding='utf-8'"
            )
            self.assert_success(response, username, {})

    def test_saml_bad_ticket(self):
        """test validation with a bad ST and a bad PT, validation should fail"""
        tickets = [utils.gen_st(), utils.gen_pt()]

        for ticket in tickets:
            client = Client()
            response = client.post(
                '/samlValidate?TARGET=%s' % self.service,
                self.xml_template % {
                    'ticket': ticket,
                    'request_id': utils.gen_saml_id(),
                    'issue_instant': timezone.now().isoformat()
                },
                content_type="text/xml; encoding='utf-8'"
            )
            self.assert_error(
                response,
                "AuthnFailed",
                'ticket %s not found' % ticket
            )

    def test_saml_bad_ticket_prefix(self):
        """test validation with a bad ticket prefix. Validation should fail with 'AuthnFailed'"""
        bad_ticket = "RANDOM-NOT-BEGINING-WITH-ST-OR-ST"
        client = Client()
        response = client.post(
            '/samlValidate?TARGET=%s' % self.service,
            self.xml_template % {
                'ticket': bad_ticket,
                'request_id': utils.gen_saml_id(),
                'issue_instant': timezone.now().isoformat()
            },
            content_type="text/xml; encoding='utf-8'"
        )
        self.assert_error(
            response,
            "AuthnFailed",
            'ticket %s should begin with PT- or ST-' % bad_ticket
        )

    def test_saml_bad_target(self):
        """test with a valid ticket, but using a bad target, validation should fail"""
        bad_target = "https://www.example.org"
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        response = client.post(
            '/samlValidate?TARGET=%s' % bad_target,
            self.xml_template % {
                'ticket': ticket.value,
                'request_id': utils.gen_saml_id(),
                'issue_instant': timezone.now().isoformat()
            },
            content_type="text/xml; encoding='utf-8'"
        )
        self.assert_error(
            response,
            "AuthnFailed",
            'TARGET %s does not match ticket service' % bad_target
        )

    def test_saml_bad_xml(self):
        """test validation with a bad xml request, validation should fail"""
        client = Client()
        response = client.post(
            '/samlValidate?TARGET=%s' % self.service,
            "<root></root>",
            content_type="text/xml; encoding='utf-8'"
        )
        self.assert_error(response, 'VersionMismatch')
