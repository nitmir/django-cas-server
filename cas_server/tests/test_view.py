"""Tests module for views"""
from cas_server.default_settings import settings

import django
from django.test import TestCase, Client
from django.test.utils import override_settings
from django.utils import timezone


import random
import json
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
    get_proxy_ticket
)
from cas_server.tests.mixin import BaseServicePattern, XmlContent


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class LoginTestCase(TestCase, BaseServicePattern):
    """Tests for the login view"""
    def setUp(self):
        """Prepare the test context:"""
        self.setup_service_patterns()

    def assert_logged(self, client, response, warn=False, code=200):
        """Assertions testing that client is well authenticated"""
        self.assertEqual(response.status_code, code)
        self.assertTrue(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )
        self.assertTrue(client.session["username"] == settings.CAS_TEST_USER)
        self.assertTrue(client.session["warn"] is warn)
        self.assertTrue(client.session["authenticated"] is True)

        self.assertTrue(
            models.User.objects.get(
                username=settings.CAS_TEST_USER,
                session_key=client.session.session_key
            )
        )

    def assert_login_failed(self, client, response, code=200):
        """Assertions testing a failed login attempt"""
        self.assertEqual(response.status_code, code)
        self.assertFalse(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )

        self.assertTrue(client.session.get("username") is None)
        self.assertTrue(client.session.get("warn") is None)
        self.assertTrue(client.session.get("authenticated") is None)

    def test_login_view_post_goodpass_goodlt(self):
        """Test a successul login"""
        client, params = get_login_page_params()
        params["username"] = settings.CAS_TEST_USER
        params["password"] = settings.CAS_TEST_PASSWORD
        self.assertTrue(params['lt'] in client.session['lt'])

        response = client.post('/login', params)
        self.assert_logged(client, response)
        # LoginTicket conssumed
        self.assertTrue(params['lt'] not in client.session['lt'])

    def test_login_view_post_goodpass_goodlt_warn(self):
        """Test a successul login requesting to be warned before creating services tickets"""
        client, params = get_login_page_params()
        params["username"] = settings.CAS_TEST_USER
        params["password"] = settings.CAS_TEST_PASSWORD
        params["warn"] = "on"

        response = client.post('/login', params)
        self.assert_logged(client, response, warn=True)

    def test_lt_max(self):
        """Check we only keep the last 100 Login Ticket for a user"""
        client, params = get_login_page_params()
        current_lt = params["lt"]
        i_in_test = random.randint(0, 99)
        i_not_in_test = random.randint(101, 150)
        for i in range(150):
            if i == i_in_test:
                self.assertTrue(current_lt in client.session['lt'])
            if i == i_not_in_test:
                self.assertTrue(current_lt not in client.session['lt'])
                self.assertTrue(len(client.session['lt']) <= 100)
            client, params = get_login_page_params(client)
        self.assertTrue(len(client.session['lt']) <= 100)

    def test_login_view_post_badlt(self):
        """Login attempt with a bad LoginTicket"""
        client, params = get_login_page_params()
        params["username"] = settings.CAS_TEST_USER
        params["password"] = settings.CAS_TEST_PASSWORD
        params["lt"] = 'LT-random'

        response = client.post('/login', params)

        self.assert_login_failed(client, response)
        self.assertTrue(b"Invalid login ticket" in response.content)

    def test_login_view_post_badpass_good_lt(self):
        """Login attempt with a bad password"""
        client, params = get_login_page_params()
        params["username"] = settings.CAS_TEST_USER
        params["password"] = "test2"
        response = client.post('/login', params)

        self.assert_login_failed(client, response)
        self.assertTrue(
            (
                b"The credentials you provided cannot be "
                b"determined to be authentic"
            ) in response.content
        )

    def assert_ticket_attributes(self, client, ticket_value):
        """check the ticket attributes in the db"""
        user = models.User.objects.get(
            username=settings.CAS_TEST_USER,
            session_key=client.session.session_key
        )
        self.assertTrue(user)
        ticket = models.ServiceTicket.objects.get(value=ticket_value)
        self.assertEqual(ticket.user, user)
        self.assertEqual(ticket.attributs, settings.CAS_TEST_ATTRIBUTES)
        self.assertEqual(ticket.validate, False)
        self.assertEqual(ticket.service_pattern, self.service_pattern)

    def assert_service_ticket(self, client, response):
        """check that a ticket is well emited when requested on a allowed service"""
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.has_header('Location'))
        self.assertTrue(
            response['Location'].startswith(
                "https://www.example.com?ticket=%s-" % settings.CAS_SERVICE_TICKET_PREFIX
            )
        )

        ticket_value = response['Location'].split('ticket=')[-1]
        self.assert_ticket_attributes(client, ticket_value)

    def test_view_login_get_allowed_service(self):
        """Request a ticket for an allowed service by an unauthenticated client"""
        client = Client()
        response = client.get("/login?service=https://www.example.com")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"Authentication required by service "
                b"example (https://www.example.com)"
            ) in response.content
        )

    def test_view_login_get_denied_service(self):
        """Request a ticket for an denied service by an unauthenticated client"""
        client = Client()
        response = client.get("/login?service=https://www.example.net")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"Service https://www.example.net non allowed" in response.content)

    def test_view_login_get_auth_allowed_service(self):
        """Request a ticket for an allowed service by an authenticated client"""
        # client is already authenticated
        client = get_auth_client()
        response = client.get("/login?service=https://www.example.com")
        self.assert_service_ticket(client, response)

    def test_view_login_get_auth_allowed_service_warn(self):
        """Request a ticket for an allowed service by an authenticated client"""
        # client is already authenticated
        client = get_auth_client(warn="on")
        response = client.get("/login?service=https://www.example.com")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"Authentication has been required by service "
                b"example (https://www.example.com)"
            ) in response.content
        )

        params = copy_form(response.context["form"])
        response = client.post("/login", params)
        self.assert_service_ticket(client, response)

    def test_view_login_get_auth_denied_service(self):
        """Request a ticket for a not allowed service by an authenticated client"""
        client = get_auth_client()
        response = client.get("/login?service=https://www.example.org")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"Service https://www.example.org non allowed" in response.content)

    def test_user_logged_not_in_db(self):
        """If the user is logged but has been delete from the database, it should be logged out"""
        client = get_auth_client()
        models.User.objects.get(
            username=settings.CAS_TEST_USER,
            session_key=client.session.session_key
        ).delete()
        response = client.get("/login")

        self.assert_login_failed(client, response, code=302)
        if django.VERSION < (1, 9):  # pragma: no cover coverage is computed with dango 1.9
            self.assertEqual(response["Location"], "http://testserver/login")
        else:
            self.assertEqual(response["Location"], "/login?")

    def test_service_restrict_user(self):
        """Testing the restric user capability fro a service"""
        client = get_auth_client()

        response = client.get("/login", {'service': self.service_restrict_user_fail})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"Username non allowed" in response.content)

        response = client.get("/login", {'service': self.service_restrict_user_success})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            response["Location"].startswith("%s?ticket=" % self.service_restrict_user_success)
        )

    def test_service_filter(self):
        """Test the filtering on user attributes"""
        client = get_auth_client()

        response = client.get("/login", {'service': self.service_filter_fail})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"User charateristics non allowed" in response.content)

        response = client.get("/login", {'service': self.service_filter_success})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("%s?ticket=" % self.service_filter_success))

    def test_service_user_field(self):
        """Test using a user attribute as username: case on if the attribute exists or not"""
        client = get_auth_client()

        response = client.get("/login", {'service': self.service_field_needed_fail})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"The attribut uid is needed to use that service" in response.content)

        response = client.get("/login", {'service': self.service_field_needed_success})
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
        client = get_auth_client()
        response = client.get("/login", {"service": self.service_field_needed_success})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"The attribut alias is needed to use that service" in response.content)

    def test_gateway(self):
        """test gateway parameter"""

        # First with an authenticated client that fail to get a ticket for a service
        service = "https://restrict_user_fail.example.com"
        client = get_auth_client()
        response = client.get("/login", {'service': service, 'gateway': 'on'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], service)

        # second for an user not yet authenticated on a valid service
        client = Client()
        response = client.get('/login', {'service': service, 'gateway': 'on'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], service)

    def test_renew(self):
        """test the authentication renewal request from a service"""
        service = "https://www.example.com"
        client = get_auth_client()
        response = client.get("/login", {'service': service, 'renew': 'on'})
        # we are ask to reauthenticate
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"Authentication renewal required by "
                b"service example (https://www.example.com)"
            ) in response.content
        )
        params = copy_form(response.context["form"])
        params["username"] = settings.CAS_TEST_USER
        params["password"] = settings.CAS_TEST_PASSWORD
        self.assertEqual(params["renew"], True)
        response = client.post("/login", params)
        self.assertEqual(response.status_code, 302)
        ticket_value = response['Location'].split('ticket=')[-1]
        ticket = models.ServiceTicket.objects.get(value=ticket_value)
        # the created ticket is marked has being gottent after a renew
        self.assertEqual(ticket.renew, True)

    def test_ajax_login_required(self):
        """test ajax, login required"""
        client = Client()
        response = client.get("/login", HTTP_X_AJAX='on')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["detail"], "login required")
        self.assertEqual(data["url"], "/login?")

    def test_ajax_logged_user_deleted(self):
        """test ajax user logged deleted: login required"""
        client = get_auth_client()
        user = models.User.objects.get(
            username=settings.CAS_TEST_USER,
            session_key=client.session.session_key
        )
        user.delete()
        response = client.get("/login", HTTP_X_AJAX='on')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["detail"], "login required")
        self.assertEqual(data["url"], "/login?")

    def test_ajax_logged(self):
        """test ajax user is successfully logged"""
        client = get_auth_client()
        response = client.get("/login", HTTP_X_AJAX='on')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["detail"], "logged")

    def test_ajax_get_ticket_success(self):
        """test ajax retrieve a ticket for an allowed service"""
        service = "https://www.example.com"
        client = get_auth_client()
        response = client.get("/login", {'service': service}, HTTP_X_AJAX='on')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["detail"], "auth")
        self.assertTrue(data["url"].startswith('%s?ticket=' % service))

    def test_ajax_get_ticket_fail(self):
        """test ajax retrieve a ticket for a denied service"""
        service = "https://www.example.org"
        client = get_auth_client()
        response = client.get("/login", {'service': service}, HTTP_X_AJAX='on')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["detail"], "auth")
        self.assertEqual(data["messages"][0]["level"], "error")
        self.assertEqual(
            data["messages"][0]["message"],
            "Service https://www.example.org non allowed."
        )

    def test_ajax_get_ticket_warn(self):
        """test get a ticket but user asked to be warned"""
        service = "https://www.example.com"
        client = get_auth_client(warn="on")
        response = client.get("/login", {'service': service}, HTTP_X_AJAX='on')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["detail"], "confirmation needed")


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class LogoutTestCase(TestCase):
    """test fot the logout view"""
    def test_logout(self):
        """logout is idempotent"""
        client = Client()

        client.get("/logout")

        self.assertFalse(client.session.get("username"))
        self.assertFalse(client.session.get("authenticated"))

    def test_logout_view(self):
        """test simple logout"""
        client = get_auth_client()
        client2 = get_auth_client()

        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )
        self.assertTrue(client.session["username"] == settings.CAS_TEST_USER)
        self.assertTrue(client.session["authenticated"] is True)

        response = client.get("/logout")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"You have successfully logged out from "
                b"the Central Authentication Service"
            ) in response.content
        )

        self.assertFalse(client.session.get("username"))
        self.assertFalse(client.session.get("authenticated"))
        # client2 is still logged
        self.assertTrue(client2.session["username"] == settings.CAS_TEST_USER)
        self.assertTrue(client2.session["authenticated"] is True)

        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )

    def test_logout_from_all_session(self):
        """test logout from all my session"""
        client = get_auth_client()
        client2 = get_auth_client()

        client.get("/logout?all=1")

        # both client are logged out
        self.assertFalse(client.session.get("username"))
        self.assertFalse(client.session.get("authenticated"))
        self.assertFalse(client2.session.get("username"))
        self.assertFalse(client2.session.get("authenticated"))

    def assert_redirect_to_service(self, client, response):
        """assert logout redirect to parameter"""
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.has_header("Location"))
        self.assertEqual(response["Location"], "https://www.example.com")

        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )

    def test_logout_view_url(self):
        """test logout redirect to url parameter"""
        client = get_auth_client()

        response = client.get('/logout?url=https://www.example.com')
        self.assert_redirect_to_service(client, response)

    def test_logout_view_service(self):
        """test logout redirect to service parameter"""
        client = get_auth_client()

        response = client.get('/logout?service=https://www.example.com')
        self.assert_redirect_to_service(client, response)

    def test_ajax_logout(self):
        """test ajax logout"""
        client = get_auth_client()

        response = client.get('/logout', HTTP_X_AJAX='on')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["detail"], "logout")
        self.assertEqual(data['session_nb'], 1)

    def test_ajax_logout_all_session(self):
        """test ajax logout from a random number a sessions"""
        nb_client = random.randint(2, 10)
        clients = [get_auth_client() for i in range(nb_client)]
        response = clients[0].get('/logout?all=1', HTTP_X_AJAX='on')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["detail"], "logout")
        self.assertEqual(data['session_nb'], nb_client)

    @override_settings(CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT=True)
    def test_redirect_after_logout(self):
        """Test redirect to login after logout parameter"""
        client = get_auth_client()

        response = client.get('/logout')
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
        client = get_auth_client()

        response = client.get('/logout?url=https://www.example.com')
        self.assert_redirect_to_service(client, response)

        response = client.get('/logout?service=https://www.example.com')
        self.assert_redirect_to_service(client, response)

    @override_settings(CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT=True)
    def test_ajax_redirect_after_logout(self):
        """Test ajax redirect to login after logout parameter"""
        client = get_auth_client()

        response = client.get('/logout', HTTP_X_AJAX='on')
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
        self.service = 'https://www.example.com'
        models.ServicePattern.objects.create(
            name="example",
            pattern="^https://www\.example\.com(/.*)?$"
        )

    @override_settings(CAS_AUTH_SHARED_SECRET='test')
    def test_auth_view_goodpass(self):
        """successful request are awsered by yes"""
        client = get_auth_client()
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
        self.assertEqual(response.content, b'yes\n')

    @override_settings(CAS_AUTH_SHARED_SECRET='test')
    def test_auth_view_goodpass_logged(self):
        """successful request are awsered by yes, using a logged sessions"""
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
        self.service = 'https://www.example.com'
        self.service_pattern = models.ServicePattern.objects.create(
            name="example",
            pattern="^https://www\.example\.com(/.*)?$"
        )
        self.service_user_field = "https://user_field.example.com"
        self.service_pattern_user_field = models.ServicePattern.objects.create(
            name="user field",
            pattern="^https://user_field\.example\.com(/.*)?$",
            user_field="alias"
        )
        self.service_user_field_alt = "https://user_field_alt.example.com"
        self.service_pattern_user_field_alt = models.ServicePattern.objects.create(
            name="user field alt",
            pattern="^https://user_field_alt\.example\.com(/.*)?$",
            user_field="nom"
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

    def test_validate_view_ok(self):
        """test for a valid (ticket, service)"""
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        response = client.get('/validate', {'ticket': ticket.value, 'service': self.service})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'yes\ntest\n')

    def test_validate_view_badservice(self):
        """test for a valid ticket but bad service"""
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        response = client.get(
            '/validate',
            {'ticket': ticket.value, 'service': "https://www.example.org"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'no\n')

    def test_validate_view_badticket(self):
        """test for a bad ticket but valid service"""
        get_user_ticket_request(self.service)

        client = Client()
        response = client.get(
            '/validate',
            {'ticket': "%s-RANDOM" % settings.CAS_SERVICE_TICKET_PREFIX, 'service': self.service}
        )
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
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b'no\n')


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class ValidateServiceTestCase(TestCase, XmlContent):
    """tests for the serviceValidate view"""
    def setUp(self):
        """preparing test context"""
        self.service = 'http://127.0.0.1:45678'
        self.service_pattern = models.ServicePattern.objects.create(
            name="localhost",
            pattern="^https?://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
            proxy_callback=True
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

        self.service_user_field = "https://user_field.example.com"
        self.service_pattern_user_field = models.ServicePattern.objects.create(
            name="user field",
            pattern="^https://user_field\.example\.com(/.*)?$",
            user_field="alias"
        )
        self.service_user_field_alt = "https://user_field_alt.example.com"
        self.service_pattern_user_field_alt = models.ServicePattern.objects.create(
            name="user field alt",
            pattern="^https://user_field_alt\.example\.com(/.*)?$",
            user_field="nom"
        )

        self.service_one_attribute = "https://one_attribute.example.com"
        self.service_pattern_one_attribute = models.ServicePattern.objects.create(
            name="one_attribute",
            pattern="^https://one_attribute\.example\.com(/.*)?$"
        )
        models.ReplaceAttributName.objects.create(
            name="nom",
            service_pattern=self.service_pattern_one_attribute
        )

    def test_validate_service_view_ok(self):
        """test with a valid (ticket, service), the username and all attributes are transmited"""
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        response = client.get('/serviceValidate', {'ticket': ticket.value, 'service': self.service})
        self.assert_success(response, settings.CAS_TEST_USER, settings.CAS_TEST_ATTRIBUTES)

    def test_validate_service_view_ok_one_attribute(self):
        """
            test with a valid (ticket, service), the username and
            the 'nom' only attribute are transmited
        """
        ticket = get_user_ticket_request(self.service_one_attribute)[1]

        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': self.service_one_attribute}
        )
        self.assert_success(
            response,
            settings.CAS_TEST_USER,
            {'nom': settings.CAS_TEST_ATTRIBUTES['nom']}
        )

    def test_validate_service_view_badservice(self):
        """test with a valid ticket but a bad service, the validatin should fail"""
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        bad_service = "https://www.example.org"
        response = client.get('/serviceValidate', {'ticket': ticket.value, 'service': bad_service})
        self.assert_error(
            response,
            "INVALID_SERVICE",
            bad_service
        )

    def test_validate_service_view_badticket_goodprefix(self):
        """
            test with a good service bud a bad ticket begining with ST-,
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
        (httpd, host, port) = utils.HttpParamsHandler.run()[0:3]
        service = "http://%s:%s" % (host, port)

        ticket = get_user_ticket_request(service)[1]

        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': service, 'pgtUrl': service}
        )
        pgt_params = httpd.PARAMS
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        pgtiou = root.xpath(
            "//cas:proxyGrantingTicket",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(pgtiou), 1)
        self.assertEqual(pgt_params["pgtIou"], pgtiou[0].text)
        self.assertTrue("pgtId" in pgt_params)

    def test_validate_service_pgturl_sslerror(self):
        """test the retrieval of a ProxyGrantingTicket with a SSL error on the pgtUrl"""
        (host, port) = utils.HttpParamsHandler.run()[1:3]
        service = "https://%s:%s" % (host, port)

        ticket = get_user_ticket_request(service)[1]

        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': service, 'pgtUrl': service}
        )
        self.assert_error(
            response,
            "INVALID_PROXY_CALLBACK",
        )

    def test_validate_service_pgturl_404(self):
        """
            test the retrieval on a ProxyGrantingTicket then to pgtUrl return a http error.
            PGT creation should be aborted but the ticket still be valid
        """
        (host, port) = utils.Http404Handler.run()[1:3]
        service = "http://%s:%s" % (host, port)

        ticket = get_user_ticket_request(service)[1]
        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': service, 'pgtUrl': service}
        )
        root = self.assert_success(response, settings.CAS_TEST_USER, settings.CAS_TEST_ATTRIBUTES)
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
            ticket = get_user_ticket_request(service)[1]
            client = Client()
            response = client.get(
                '/serviceValidate',
                {'ticket': ticket.value, 'service': service}
            )
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
        self.setup_service_patterns(proxy=True)

        self.service = 'http://127.0.0.1'
        self.service_pattern = models.ServicePattern.objects.create(
            name="localhost",
            pattern="^http://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
            proxy=True,
            proxy_callback=True
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

    def test_validate_proxy_ok(self):
        """
            Get a PGT, get a proxy ticket, validate it. Validation should succeed and
            show the proxy service URL.
        """
        params = get_pgt()

        # get a proxy ticket
        client1 = Client()
        response = client1.get('/proxy', {'pgt': params['pgtId'], 'targetService': self.service})
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        sucess = root.xpath("//cas:proxySuccess", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertTrue(sucess)

        proxy_ticket = root.xpath(
            "//cas:proxyTicket",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(proxy_ticket), 1)
        proxy_ticket = proxy_ticket[0].text

        # validate the proxy ticket
        client2 = Client()
        response = client2.get('/proxyValidate', {'ticket': proxy_ticket, 'service': self.service})
        root = self.assert_success(
            response,
            settings.CAS_TEST_USER,
            settings.CAS_TEST_ATTRIBUTES
        )

        # check that the proxy is send to the end service
        proxies = root.xpath("//cas:proxies", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(proxies), 1)
        proxy = proxies[0].xpath("//cas:proxy", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(proxy), 1)
        self.assertEqual(proxy[0].text, params["service"])

    def test_validate_proxy_bad_pgt(self):
        """Try to get a ProxyTicket with a bad PGT. The PT generation should fail"""
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
        params = get_pgt()

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

        # service do not allow proxy ticket
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
            'the service %s do not allow proxy ticket' % params['service']
        )

        self.service_pattern.proxy = True
        self.service_pattern.save()

    def test_proxy_unauthorized_user(self):
        """
            Try to get a PT for services that do not allow the current user:
                * first with a service that restrict allower username
                * second with a service requiring somes conditions on the user attributes
                * third with a service using a particular user attribute as username
            All this tests should fail
        """
        params = get_pgt()

        for service in [
            self.service_restrict_user_fail,
            self.service_filter_fail,
            self.service_field_needed_fail
        ]:
            client = Client()
            response = client.get(
                '/proxy',
                {'pgt': params['pgtId'], 'targetService': service}
            )
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
        self.setup_service_patterns(proxy=True)

        self.service_pgt = 'http://127.0.0.1'
        self.service_pattern_pgt = models.ServicePattern.objects.create(
            name="localhost",
            pattern="^http://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
            proxy=True,
            proxy_callback=True
        )
        models.ReplaceAttributName.objects.create(
            name="*",
            service_pattern=self.service_pattern_pgt
        )

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
        root = etree.fromstring(response.content)
        success = root.xpath(
            "//samlp:StatusCode",
            namespaces={'samlp': "urn:oasis:names:tc:SAML:1.0:protocol"}
        )
        self.assertEqual(len(success), 1)
        self.assertTrue(success[0].attrib['Value'].endswith(":Success"))

        user = root.xpath(
            "//samla:NameIdentifier",
            namespaces={'samla': "urn:oasis:names:tc:SAML:1.0:assertion"}
        )
        self.assertTrue(user)
        self.assertEqual(user[0].text, username)

        attributes = root.xpath(
            "//samla:AttributeStatement/samla:Attribute",
            namespaces={'samla': "urn:oasis:names:tc:SAML:1.0:assertion"}
        )
        attrs = set()
        for attr in attributes:
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
        root = etree.fromstring(response.content)
        error = root.xpath(
            "//samlp:StatusCode",
            namespaces={'samlp': "urn:oasis:names:tc:SAML:1.0:protocol"}
        )
        self.assertEqual(len(error), 1)
        self.assertTrue(error[0].attrib['Value'].endswith(":%s" % code))
        if msg is not None:
            self.assertEqual(error[0].text, msg)

    def test_saml_ok(self):
        """
            test with a valid (ticket, service), with a ST and a PT,
            the username and all attributes are transmited"""
        tickets = [
            get_user_ticket_request(self.service)[1],
            get_proxy_ticket(self.service)
        ]

        for ticket in tickets:
            client = Client()
            response = client.post(
                '/samlValidate?TARGET=%s' % self.service,
                self.xml_template % {
                    'ticket': ticket.value,
                    'request_id': utils.gen_saml_id(),
                    'issue_instant': timezone.now().isoformat()
                },
                content_type="text/xml; encoding='utf-8'"
            )
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
        """test with a valid(ticket, service), but using a bad target"""
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
            'TARGET %s do not match ticket service' % bad_target
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
