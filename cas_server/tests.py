from .default_settings import settings

import django
from django.test import TestCase
from django.test import Client

import re
import six
import random
import json
from lxml import etree
from six.moves import range

from cas_server import models
from cas_server import utils


def copy_form(form):
    """Copy form value into a dict"""
    params = {}
    for field in form:
        if field.value():
            params[field.name] = field.value()
        else:
            params[field.name] = ""
    return params


def get_login_page_params(client=None):
    """Return a client and the POST params for the client to login"""
    if client is None:
        client = Client()
    response = client.get('/login')
    params = copy_form(response.context["form"])
    return client, params


def get_auth_client(**update):
    """return a authenticated client"""
    client, params = get_login_page_params()
    params["username"] = settings.CAS_TEST_USER
    params["password"] = settings.CAS_TEST_PASSWORD
    params.update(update)

    client.post('/login', params)
    return client


def get_user_ticket_request(service):
    """Make an auth client to request a ticket for `service`, return the tuple (user, ticket)"""
    client = get_auth_client()
    response = client.get("/login", {"service": service})
    ticket_value = response['Location'].split('ticket=')[-1]
    user = models.User.objects.get(
        username=settings.CAS_TEST_USER,
        session_key=client.session.session_key
    )
    ticket = models.ServiceTicket.objects.get(value=ticket_value)
    return (user, ticket)


def get_pgt():
    """return a dict contening a service, user and PGT ticket for this service"""
    (host, port) = utils.PGTUrlHandler.run()[1:3]
    service = "http://%s:%s" % (host, port)

    (user, ticket) = get_user_ticket_request(service)

    client = Client()
    client.get('/serviceValidate', {'ticket': ticket.value, 'service': service, 'pgtUrl': service})
    params = utils.PGTUrlHandler.PARAMS.copy()

    params["service"] = service
    params["user"] = user

    return params


class CheckPasswordCase(TestCase):
    """Tests for the utils function `utils.check_password`"""

    def setUp(self):
        """Generate random bytes string that will be used ass passwords"""
        self.password1 = utils.gen_saml_id()
        self.password2 = utils.gen_saml_id()
        if not isinstance(self.password1, bytes):
            self.password1 = self.password1.encode("utf8")
            self.password2 = self.password2.encode("utf8")

    def test_setup(self):
        """check that generated password are bytes"""
        self.assertIsInstance(self.password1, bytes)
        self.assertIsInstance(self.password2, bytes)

    def test_plain(self):
        """test the plain auth method"""
        self.assertTrue(utils.check_password("plain", self.password1, self.password1, "utf8"))
        self.assertFalse(utils.check_password("plain", self.password1, self.password2, "utf8"))

    def test_crypt(self):
        """test the crypt auth method"""
        if six.PY3:
            hashed_password1 = utils.crypt.crypt(
                self.password1.decode("utf8"),
                "$6$UVVAQvrMyXMF3FF3"
            ).encode("utf8")
        else:
            hashed_password1 = utils.crypt.crypt(self.password1, "$6$UVVAQvrMyXMF3FF3")

        self.assertTrue(utils.check_password("crypt", self.password1, hashed_password1, "utf8"))
        self.assertFalse(utils.check_password("crypt", self.password2, hashed_password1, "utf8"))

    def test_ldap_ssha(self):
        """test the ldap auth method with a {SSHA} scheme"""
        salt = b"UVVAQvrMyXMF3FF3"
        hashed_password1 = utils.LdapHashUserPassword.hash(b'{SSHA}', self.password1, salt, "utf8")

        self.assertIsInstance(hashed_password1, bytes)
        self.assertTrue(utils.check_password("ldap", self.password1, hashed_password1, "utf8"))
        self.assertFalse(utils.check_password("ldap", self.password2, hashed_password1, "utf8"))

    def test_hex_md5(self):
        """test the hex_md5 auth method"""
        hashed_password1 = utils.hashlib.md5(self.password1).hexdigest()

        self.assertTrue(utils.check_password("hex_md5", self.password1, hashed_password1, "utf8"))
        self.assertFalse(utils.check_password("hex_md5", self.password2, hashed_password1, "utf8"))

    def test_hex_sha512(self):
        """test the hex_sha512 auth method"""
        hashed_password1 = utils.hashlib.sha512(self.password1).hexdigest()

        self.assertTrue(
            utils.check_password("hex_sha512", self.password1, hashed_password1, "utf8")
        )
        self.assertFalse(
            utils.check_password("hex_sha512", self.password2, hashed_password1, "utf8")
        )


class LoginTestCase(TestCase):
    """Tests for the login view"""
    def setUp(self):
        """
            Prepare the test context:
                * set the auth class to 'cas_server.auth.TestAuthUser'
                * create a service pattern for https://www.example.com/**
                * Set the service pattern to return all user attributes
        """
        settings.CAS_AUTH_CLASS = 'cas_server.auth.TestAuthUser'

        # For general purpose testing
        self.service_pattern = models.ServicePattern.objects.create(
            name="example",
            pattern="^https://www\.example\.com(/.*)?$",
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

        # For testing the restrict_users attributes
        self.service_pattern_restrict_user_fail = models.ServicePattern.objects.create(
            name="restrict_user_fail",
            pattern="^https://restrict_user_fail\.example\.com(/.*)?$",
            restrict_users=True,
        )
        self.service_pattern_restrict_user_success = models.ServicePattern.objects.create(
            name="restrict_user_success",
            pattern="^https://restrict_user_success\.example\.com(/.*)?$",
            restrict_users=True,
        )
        models.Username.objects.create(
            value=settings.CAS_TEST_USER,
            service_pattern=self.service_pattern_restrict_user_success
        )

        # For testing the user attributes filtering conditions
        self.service_pattern_filter_fail = models.ServicePattern.objects.create(
            name="filter_fail",
            pattern="^https://filter_fail\.example\.com(/.*)?$",
        )
        models.FilterAttributValue.objects.create(
            attribut="right",
            pattern="^admin$",
            service_pattern=self.service_pattern_filter_fail
        )
        self.service_pattern_filter_success = models.ServicePattern.objects.create(
            name="filter_success",
            pattern="^https://filter_success\.example\.com(/.*)?$",
        )
        models.FilterAttributValue.objects.create(
            attribut="email",
            pattern="^%s$" % re.escape(settings.CAS_TEST_ATTRIBUTES['email']),
            service_pattern=self.service_pattern_filter_success
        )

        # For testing the user_field attributes
        self.service_pattern_field_needed_fail = models.ServicePattern.objects.create(
            name="field_needed_fail",
            pattern="^https://field_needed_fail\.example\.com(/.*)?$",
            user_field="uid"
        )
        self.service_pattern_field_needed_success = models.ServicePattern.objects.create(
            name="field_needed_success",
            pattern="^https://field_needed_success\.example\.com(/.*)?$",
            user_field="nom"
        )

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
        if django.VERSION < (1, 9):
            self.assertEqual(response["Location"], "http://testserver/login")
        else:
            self.assertEqual(response["Location"], "/login?")

    def test_service_restrict_user(self):
        """Testing the restric user capability fro a service"""
        service = "https://restrict_user_fail.example.com"
        client = get_auth_client()
        response = client.get("/login", {'service': service})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"Username non allowed" in response.content)

        service = "https://restrict_user_success.example.com"
        response = client.get("/login", {'service': service})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("%s?ticket=" % service))

    def test_service_filter(self):
        """Test the filtering on user attributes"""
        service = "https://filter_fail.example.com"
        client = get_auth_client()
        response = client.get("/login", {'service': service})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"User charateristics non allowed" in response.content)

        service = "https://filter_success.example.com"
        response = client.get("/login", {'service': service})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("%s?ticket=" % service))

    def test_service_user_field(self):
        """Test using a user attribute as username: case on if the attribute exists or not"""
        service = "https://field_needed_fail.example.com"
        client = get_auth_client()
        response = client.get("/login", {'service': service})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"The attribut uid is needed to use that service" in response.content)

        service = "https://field_needed_success.example.com"
        response = client.get("/login", {'service': service})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("%s?ticket=" % service))

    def test_service_user_field_evaluate_to_false(self):
        """
            Test using a user attribute as username:
            case the attribute exists but evaluate to False
        """
        service = "https://field_needed_success.example.com"
        saved_nom = settings.CAS_TEST_ATTRIBUTES["nom"]
        settings.CAS_TEST_ATTRIBUTES["nom"] = []

        client = get_auth_client()
        response = client.get("/login", {"service": service})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"The attribut nom is needed to use that service" in response.content)

        settings.CAS_TEST_ATTRIBUTES["nom"] = saved_nom

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


class LogoutTestCase(TestCase):

    def setUp(self):
        """prepare logout test context"""
        settings.CAS_AUTH_CLASS = 'cas_server.auth.TestAuthUser'

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

    def test_redirect_after_logout(self):
        """Test redirect to login after logout parameter"""
        settings.CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT = True
        client = get_auth_client()

        response = client.get('/logout')
        self.assertEqual(response.status_code, 302)
        if django.VERSION < (1, 9):
            self.assertEqual(response["Location"], "http://testserver/login")
        else:
            self.assertEqual(response["Location"], "/login")
        self.assertFalse(client.session.get("username"))
        self.assertFalse(client.session.get("authenticated"))

        settings.CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT = False

    def test_redirect_after_logout_to_service(self):
        """test prevalence of redirect url/service parameter over redirect to login after logout"""
        settings.CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT = True
        client = get_auth_client()

        response = client.get('/logout?url=https://www.example.com')
        self.assert_redirect_to_service(client, response)

        response = client.get('/logout?service=https://www.example.com')
        self.assert_redirect_to_service(client, response)

        settings.CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT = False

    def test_ajax_redirect_after_logout(self):
        """Test ajax redirect to login after logout parameter"""
        settings.CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT = True
        client = get_auth_client()

        response = client.get('/logout', HTTP_X_AJAX='on')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content.decode("utf8"))
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["detail"], "logout")
        self.assertEqual(data['session_nb'], 1)
        self.assertEqual(data['url'], '/login')

        settings.CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT = False


class AuthTestCase(TestCase):
    """
        Test for the auth view, used for external services
        to validate (user, pass, service) tuples.
    """
    def setUp(self):
        """preparing test context"""
        settings.CAS_AUTH_CLASS = 'cas_server.auth.TestAuthUser'
        self.service = 'https://www.example.com'
        models.ServicePattern.objects.create(
            name="example",
            pattern="^https://www\.example\.com(/.*)?$"
        )

    def test_auth_view_goodpass(self):
        """successful request are awsered by yes"""
        settings.CAS_AUTH_SHARED_SECRET = 'test'
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

    def test_auth_view_badpass(self):
        """ bag user password => no"""
        settings.CAS_AUTH_SHARED_SECRET = 'test'
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

    def test_auth_view_badservice(self):
        """bad service => no"""
        settings.CAS_AUTH_SHARED_SECRET = 'test'
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

    def test_auth_view_badsecret(self):
        """bad api key => no"""
        settings.CAS_AUTH_SHARED_SECRET = 'test'
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
        settings.CAS_AUTH_SHARED_SECRET = None
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

    def test_auth_view_missing_parameter(self):
        """missing parameter in request => no"""
        settings.CAS_AUTH_SHARED_SECRET = 'test'
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


class ValidateTestCase(TestCase):
    """tests for the validate view"""
    def setUp(self):
        """preparing test context"""
        settings.CAS_AUTH_CLASS = 'cas_server.auth.TestAuthUser'
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
        ticket = get_user_ticket_request(self.service_user_field)[1]
        client = Client()
        response = client.get(
            '/validate',
            {'ticket': ticket.value, 'service': self.service_user_field}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'yes\ndemo1\n')

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


class ValidateServiceTestCase(TestCase):
    """tests for the serviceValidate view"""
    def setUp(self):
        """preparing test context"""
        settings.CAS_AUTH_CLASS = 'cas_server.auth.TestAuthUser'
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
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        sucess = root.xpath(
            "//cas:authenticationSuccess",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertTrue(sucess)

        users = root.xpath("//cas:user", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].text, settings.CAS_TEST_USER)

        attributes = root.xpath(
            "//cas:attributes",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(attributes), 1)
        attrs1 = set()
        for attr in attributes[0]:
            attrs1.add((attr.tag[len("http://www.yale.edu/tp/cas")+2:], attr.text))

        attributes = root.xpath("//cas:attribute", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(attributes), len(attrs1))
        attrs2 = set()
        for attr in attributes:
            attrs2.add((attr.attrib['name'], attr.attrib['value']))
        original = set()
        for key, value in settings.CAS_TEST_ATTRIBUTES.items():
            if isinstance(value, list):
                for sub_value in value:
                    original.add((key, sub_value))
            else:
                original.add((key, value))
        self.assertEqual(attrs1, attrs2)
        self.assertEqual(attrs1, original)

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
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        sucess = root.xpath(
            "//cas:authenticationSuccess",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertTrue(sucess)

        users = root.xpath("//cas:user", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].text, settings.CAS_TEST_USER)

        attributes = root.xpath(
            "//cas:attributes",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(attributes), 1)
        attrs1 = set()
        for attr in attributes[0]:
            attrs1.add((attr.tag[len("http://www.yale.edu/tp/cas")+2:], attr.text))

        attributes = root.xpath("//cas:attribute", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(attributes), len(attrs1))
        attrs2 = set()
        for attr in attributes:
            attrs2.add((attr.attrib['name'], attr.attrib['value']))
        original = set([('nom', settings.CAS_TEST_ATTRIBUTES['nom'])])
        self.assertEqual(attrs1, attrs2)
        self.assertEqual(attrs1, original)

    def test_validate_service_view_badservice(self):
        """test with a valid ticket but a bad service, the validatin should fail"""
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        bad_service = "https://www.example.org"
        response = client.get('/serviceValidate', {'ticket': ticket.value, 'service': bad_service})
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        error = root.xpath(
            "//cas:authenticationFailure",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].attrib['code'], "INVALID_SERVICE")
        self.assertEqual(error[0].text, bad_service)

    def test_validate_service_view_badticket_goodprefix(self):
        """
            test with a good service bud a bad ticket begining with ST-,
            the validation should fail with the error (INVALID_TICKET, ticket not found)
        """
        get_user_ticket_request(self.service)

        client = Client()
        bad_ticket = "%s-RANDOM" % settings.CAS_SERVICE_TICKET_PREFIX
        response = client.get('/serviceValidate', {'ticket': bad_ticket, 'service': self.service})
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        error = root.xpath(
            "//cas:authenticationFailure",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].attrib['code'], "INVALID_TICKET")
        self.assertEqual(error[0].text, 'ticket not found')

    def test_validate_service_view_badticket_badprefix(self):
        """
            test with a good service bud a bad ticket not begining with ST-,
            the validation should fail with the error (INVALID_TICKET, `the ticket`)
        """
        get_user_ticket_request(self.service)

        client = Client()
        bad_ticket = "RANDOM"
        response = client.get('/serviceValidate', {'ticket': bad_ticket, 'service': self.service})
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        error = root.xpath(
            "//cas:authenticationFailure",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].attrib['code'], "INVALID_TICKET")
        self.assertEqual(error[0].text, bad_ticket)

    def test_validate_service_view_ok_pgturl(self):
        """test the retrieval of a ProxyGrantingTicket"""
        (host, port) = utils.PGTUrlHandler.run()[1:3]
        service = "http://%s:%s" % (host, port)

        ticket = get_user_ticket_request(service)[1]

        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': service, 'pgtUrl': service}
        )
        pgt_params = utils.PGTUrlHandler.PARAMS.copy()
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
        (host, port) = utils.PGTUrlHandler.run()[1:3]
        service = "https://%s:%s" % (host, port)

        ticket = get_user_ticket_request(service)[1]

        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': service, 'pgtUrl': service}
        )
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        error = root.xpath(
            "//cas:authenticationFailure",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].attrib['code'], "INVALID_PROXY_CALLBACK")

    def test_validate_service_pgturl_404(self):
        """
            test the retrieval on a ProxyGrantingTicket then to pgtUrl return a http error.
            PGT creation should be aborted but the ticket still be valid
        """
        (host, port) = utils.PGTUrlHandler404.run()[1:3]
        service = "http://%s:%s" % (host, port)

        ticket = get_user_ticket_request(service)[1]
        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': service, 'pgtUrl': service}
        )
        self.assertEqual(response.status_code, 200)
        root = etree.fromstring(response.content)
        sucess = root.xpath(
            "//cas:authenticationSuccess",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertTrue(sucess)
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
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        error = root.xpath(
            "//cas:authenticationFailure",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].attrib['code'], "INVALID_PROXY_CALLBACK")
        self.assertEqual(error[0].text, "callback url not allowed by configuration")

        self.service_pattern.proxy_callback = True

        ticket = get_user_ticket_request(self.service)[1]
        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': self.service, 'pgtUrl': "https://www.example.org"}
        )
        self.assertEqual(response.status_code, 200)
        root = etree.fromstring(response.content)
        error = root.xpath(
            "//cas:authenticationFailure",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].attrib['code'], "INVALID_PROXY_CALLBACK")
        self.assertEqual(error[0].text, "callback url not allowed by configuration")

    def test_validate_user_field_ok(self):
        """
            test with a good user_field. A bad user_field (that evaluate to False)
            wont happed cause it is filtered in the login view
        """
        ticket = get_user_ticket_request(self.service_user_field)[1]
        client = Client()
        response = client.get(
            '/serviceValidate',
            {'ticket': ticket.value, 'service': self.service_user_field}
        )
        self.assertEqual(response.status_code, 200)
        root = etree.fromstring(response.content)
        sucess = root.xpath(
            "//cas:authenticationSuccess",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertTrue(sucess)

        users = root.xpath("//cas:user", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].text, settings.CAS_TEST_ATTRIBUTES["alias"][0])

    def test_validate_missing_parameter(self):
        """test with a missing GET parameter among [service, ticket]"""
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        params = {'ticket': ticket.value, 'service': self.service}
        for key in ['ticket', 'service']:
            send_params = params.copy()
            del send_params[key]
            response = client.get('/serviceValidate', send_params)
            root = etree.fromstring(response.content)
            error = root.xpath(
                "//cas:authenticationFailure",
                namespaces={'cas': "http://www.yale.edu/tp/cas"}
            )
            self.assertEqual(len(error), 1)
            self.assertEqual(error[0].attrib['code'], "INVALID_REQUEST")
            self.assertEqual(error[0].text, "you must specify a service and a ticket")


class ProxyTestCase(TestCase):

    def setUp(self):
        settings.CAS_AUTH_CLASS = 'cas_server.auth.TestAuthUser'
        self.service = 'http://127.0.0.1'
        self.service_pattern = models.ServicePattern.objects.create(
            name="localhost",
            pattern="^http://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
            proxy=True,
            proxy_callback=True
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

    def test_validate_proxy_ok(self):
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
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        sucess = root.xpath(
            "//cas:authenticationSuccess",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertTrue(sucess)

        # check that the proxy is send to the end service
        proxies = root.xpath("//cas:proxies", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(proxies), 1)
        proxy = proxies[0].xpath("//cas:proxy", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(proxy), 1)
        self.assertEqual(proxy[0].text, params["service"])

        # same tests than those for serviceValidate
        users = root.xpath("//cas:user", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].text, settings.CAS_TEST_USER)

        attributes = root.xpath(
            "//cas:attributes",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(attributes), 1)
        attrs1 = set()
        for attr in attributes[0]:
            attrs1.add((attr.tag[len("http://www.yale.edu/tp/cas")+2:], attr.text))

        attributes = root.xpath("//cas:attribute", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(attributes), len(attrs1))
        attrs2 = set()
        for attr in attributes:
            attrs2.add((attr.attrib['name'], attr.attrib['value']))
        original = set()
        for key, value in settings.CAS_TEST_ATTRIBUTES.items():
            if isinstance(value, list):
                for sub_value in value:
                    original.add((key, sub_value))
            else:
                original.add((key, value))
        self.assertEqual(attrs1, attrs2)
        self.assertEqual(attrs1, original)

    def test_validate_proxy_bad(self):
        params = get_pgt()

        # bad PGT
        client1 = Client()
        response = client1.get(
            '/proxy',
            {
                'pgt': "%s-RANDOM" % settings.CAS_PROXY_GRANTING_TICKET_PREFIX,
                'targetService': params['service']
            }
        )
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        error = root.xpath(
            "//cas:authenticationFailure",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].attrib['code'], "INVALID_TICKET")
        self.assertEqual(
            error[0].text,
            "PGT %s-RANDOM not found" % settings.CAS_PROXY_GRANTING_TICKET_PREFIX
        )

        # bad targetService
        client2 = Client()
        response = client2.get(
            '/proxy',
            {'pgt': params['pgtId'], 'targetService': "https://www.example.org"}
        )
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        error = root.xpath(
            "//cas:authenticationFailure",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].attrib['code'], "UNAUTHORIZED_SERVICE")
        self.assertEqual(error[0].text, "https://www.example.org")

        # service do not allow proxy ticket
        self.service_pattern.proxy = False
        self.service_pattern.save()

        client3 = Client()
        response = client3.get(
            '/proxy',
            {'pgt': params['pgtId'], 'targetService': params['service']}
        )
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        error = root.xpath(
            "//cas:authenticationFailure",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].attrib['code'], "UNAUTHORIZED_SERVICE")
        self.assertEqual(
            error[0].text,
            'the service %s do not allow proxy ticket' % params['service']
        )
