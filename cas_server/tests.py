from .default_settings import settings

from django.test import TestCase
from django.test import Client

from lxml import etree

from cas_server import models
from cas_server import utils


def get_login_page_params():
        client = Client()
        response = client.get('/login')
        form = response.context["form"]
        params = {}
        for field in form:
            if field.value():
                params[field.name] = field.value()
            else:
                params[field.name] = ""
        return client, params


def get_auth_client():
        client, params = get_login_page_params()
        params["username"] = settings.CAS_TEST_USER
        params["password"] = settings.CAS_TEST_PASSWORD

        client.post('/login', params)
        return client


def get_user_ticket_request(service):
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
    (host, port) = utils.PGTUrlHandler.run()[1:3]
    service = "http://%s:%s" % (host, port)

    (user, ticket) = get_user_ticket_request(service)

    client = Client()
    client.get('/serviceValidate', {'ticket': ticket.value, 'service': service, 'pgtUrl': service})
    params = utils.PGTUrlHandler.PARAMS.copy()

    params["service"] = service
    params["user"] = user

    return params


class LoginTestCase(TestCase):

    def setUp(self):
        settings.CAS_AUTH_CLASS = 'cas_server.auth.TestAuthUser'
        self.service_pattern = models.ServicePattern.objects.create(
            name="example",
            pattern="^https://www\.example\.com(/.*)?$",
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

    def test_login_view_post_goodpass_goodlt(self):
        client, params = get_login_page_params()
        params["username"] = settings.CAS_TEST_USER
        params["password"] = settings.CAS_TEST_PASSWORD

        response = client.post('/login', params)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )

        self.assertTrue(
            models.User.objects.get(
                username=settings.CAS_TEST_USER,
                session_key=client.session.session_key
            )
        )

    def test_login_view_post_badlt(self):
        client, params = get_login_page_params()
        params["username"] = settings.CAS_TEST_USER
        params["password"] = settings.CAS_TEST_PASSWORD
        params["lt"] = 'LT-random'

        response = client.post('/login', params)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"Invalid login ticket" in response.content)
        self.assertFalse(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )

    def test_login_view_post_badpass_good_lt(self):
        client, params = get_login_page_params()
        params["username"] = settings.CAS_TEST_USER
        params["password"] = "test2"
        response = client.post('/login', params)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"The credentials you provided cannot be "
                b"determined to be authentic"
            ) in response.content
        )
        self.assertFalse(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )

    def test_view_login_get_auth_allowed_service(self):
        client = get_auth_client()
        response = client.get("/login?service=https://www.example.com")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.has_header('Location'))
        self.assertTrue(
            response['Location'].startswith(
                "https://www.example.com?ticket=%s-" % settings.CAS_SERVICE_TICKET_PREFIX
            )
        )

        ticket_value = response['Location'].split('ticket=')[-1]
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

    def test_view_login_get_auth_denied_service(self):
        client = get_auth_client()
        response = client.get("/login?service=https://www.example.org")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"Service https://www.example.org non allowed" in response.content)


class LogoutTestCase(TestCase):

    def setUp(self):
        settings.CAS_AUTH_CLASS = 'cas_server.auth.TestAuthUser'

    def test_logout_view(self):
        client = get_auth_client()

        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )

        response = client.get("/logout")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            (
                b"You have successfully logged out from "
                b"the Central Authentication Service"
            ) in response.content
        )

        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ) in response.content
        )

    def test_logout_view_url(self):
        client = get_auth_client()

        response = client.get('/logout?url=https://www.example.com')
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

    def test_logout_view_service(self):
        client = get_auth_client()

        response = client.get('/logout?service=https://www.example.com')
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


class AuthTestCase(TestCase):

    def setUp(self):
        settings.CAS_AUTH_CLASS = 'cas_server.auth.TestAuthUser'
        self.service = 'https://www.example.com'
        models.ServicePattern.objects.create(
            name="example",
            pattern="^https://www\.example\.com(/.*)?$"
        )

    def test_auth_view_goodpass(self):
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


class ValidateTestCase(TestCase):

    def setUp(self):
        settings.CAS_AUTH_CLASS = 'cas_server.auth.TestAuthUser'
        self.service = 'https://www.example.com'
        self.service_pattern = models.ServicePattern.objects.create(
            name="example",
            pattern="^https://www\.example\.com(/.*)?$"
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

    def test_validate_view_ok(self):
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        response = client.get('/validate', {'ticket': ticket.value, 'service': self.service})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'yes\ntest\n')

    def test_validate_view_badservice(self):
        ticket = get_user_ticket_request(self.service)[1]

        client = Client()
        response = client.get(
            '/validate',
            {'ticket': ticket.value, 'service': "https://www.example.org"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'no\n')

    def test_validate_view_badticket(self):
        get_user_ticket_request(self.service)

        client = Client()
        response = client.get(
            '/validate',
            {'ticket': "%s-RANDOM" % settings.CAS_SERVICE_TICKET_PREFIX, 'service': self.service}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'no\n')


class ValidateServiceTestCase(TestCase):

    def setUp(self):
        settings.CAS_AUTH_CLASS = 'cas_server.auth.TestAuthUser'
        self.service = 'http://127.0.0.1:45678'
        self.service_pattern = models.ServicePattern.objects.create(
            name="localhost",
            pattern="^http://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
            proxy_callback=True
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

    def test_validate_service_view_ok(self):
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
        attrs1 = {}
        for attr in attributes[0]:
            attrs1[attr.tag[len("http://www.yale.edu/tp/cas")+2:]] = attr.text

        attributes = root.xpath("//cas:attribute", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(attributes), len(attrs1))
        attrs2 = {}
        for attr in attributes:
            attrs2[attr.attrib['name']] = attr.attrib['value']
        self.assertEqual(attrs1, attrs2)
        self.assertEqual(attrs1, settings.CAS_TEST_ATTRIBUTES)

    def test_validate_service_view_badservice(self):
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

    def test_validate_service_pgturl_bad_proxy_callback(self):
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
        attrs1 = {}
        for attr in attributes[0]:
            attrs1[attr.tag[len("http://www.yale.edu/tp/cas")+2:]] = attr.text

        attributes = root.xpath("//cas:attribute", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(attributes), len(attrs1))
        attrs2 = {}
        for attr in attributes:
            attrs2[attr.attrib['name']] = attr.attrib['value']
        self.assertEqual(attrs1, attrs2)
        self.assertEqual(attrs1, settings.CAS_TEST_ATTRIBUTES)

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
