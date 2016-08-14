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
"""tests for the CAS federate mode"""
from cas_server import default_settings
from cas_server.default_settings import settings

import django
from django.test import TestCase, Client
from django.test.utils import override_settings

from six.moves import reload_module

from cas_server import utils, models
from cas_server.tests.mixin import BaseServicePattern, CanLogin, FederatedIendityProviderModel
from cas_server.tests import utils as tests_utils

PROVIDERS = {
    "example.com": ("http://127.0.0.1:8080", '1', "Example dot com"),
    "example.org": ("http://127.0.0.1:8081", '2', "Example dot org"),
    "example.net": ("http://127.0.0.1:8082", '3', "Example dot net"),
    "example.test": ("http://127.0.0.1:8083", 'CAS_2_SAML_1_0', 'Example fot test'),
}


@override_settings(
    CAS_FEDERATE=True,
    CAS_AUTH_CLASS="cas_server.auth.CASFederateAuth",
    # test with a non ascii username
    CAS_TEST_USER=u"dédé"
)
class FederateAuthLoginLogoutTestCase(
    TestCase, BaseServicePattern, CanLogin, FederatedIendityProviderModel
):
    """tests for the views login logout and federate then the federated mode is enabled"""
    def setUp(self):
        """Prepare the test context"""
        self.setup_service_patterns()
        self.setup_federated_identity_provider(PROVIDERS)

    def test_default_settings(self):
        """default settings should populated some default variable then CAS_FEDERATE is True"""
        del settings.CAS_AUTH_CLASS
        reload_module(default_settings)
        self.assertEqual(settings.CAS_AUTH_CLASS, "cas_server.auth.CASFederateAuth")

    def test_login_get_provider(self):
        """some assertion about the login page in federated mode"""
        client = Client()
        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        for provider in models.FederatedIendityProvider.objects.all():
            self.assertTrue('<option value="%s">%s</option>' % (
                provider.suffix,
                provider.verbose_name
            ) in response.content.decode("utf-8"))
        self.assertEqual(response.context['post_url'], '/federate')

    def test_login_post_provider(self, remember=False):
        """test a successful login wrokflow"""
        tickets = []
        # choose the example.com provider
        for (suffix, cas_port) in [
            ("example.com", 8080), ("example.org", 8081),
            ("example.net", 8082), ("example.test", 8083)
        ]:
            provider = models.FederatedIendityProvider.objects.get(suffix=suffix)
            # get a bare client
            client = Client()
            # fetch the login page
            response = client.get("/login")
            # in federated mode, we shoudl POST do /federate on the login page
            self.assertEqual(response.context['post_url'], '/federate')
            # get current form parameter
            params = tests_utils.copy_form(response.context["form"])
            params['provider'] = provider.suffix
            if remember:
                params['remember'] = 'on'
            # just try for one suffix
            if suffix == "example.com":
                # if renew=False is posted it should be ignored
                params["renew"] = False
            # post the choosed provider
            response = client.post('/federate', params)
            # we are redirected to the provider CAS client url
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response["Location"], '%s/federate/%s%s' % (
                'http://testserver' if django.VERSION < (1, 9) else "",
                provider.suffix,
                "?remember=on" if remember else ""
            ))
            # let's follow the redirect
            response = client.get(
                '/federate/%s%s' % (provider.suffix, "?remember=on" if remember else "")
            )
            # we are redirected to the provider CAS for authentication
            self.assertEqual(response.status_code, 302)
            self.assertEqual(
                response["Location"],
                "%s/login?service=http%%3A%%2F%%2Ftestserver%%2Ffederate%%2F%s%s" % (
                    provider.server_url,
                    provider.suffix,
                    "%3Fremember%3Don" if remember else ""
                )
            )
            # let's generate a ticket
            ticket = utils.gen_st()
            # we lauch a dummy CAS server that only validate once for the service
            # http://testserver/federate/example.com with `ticket`
            tests_utils.DummyCAS.run(
                ("http://testserver/federate/%s%s" % (
                    provider.suffix,
                    "?remember=on" if remember else ""
                )).encode("ascii"),
                ticket.encode("ascii"),
                settings.CAS_TEST_USER.encode("utf8"),
                [],
                cas_port
            )
            # we normally provide a good ticket and should be redirected to /login as the ticket
            # get successfully validated again the dummy CAS
            response = client.get(
                '/federate/%s' % provider.suffix,
                {'ticket': ticket, 'remember': 'on' if remember else ''}
            )
            if remember:
                self.assertIn("remember_provider", client.cookies)
                self.assertEqual(client.cookies["remember_provider"].value, provider.suffix)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response["Location"], "%s/login" % (
                'http://testserver' if django.VERSION < (1, 9) else ""
            ))
            # follow the redirect
            response = client.get("/login")
            # we should get a page with a from with all widget hidden that auto POST to /login using
            # javascript. If javascript is disabled, a "connect" button is showed
            self.assertTrue(response.context['auto_submit'])
            self.assertEqual(response.context['post_url'], '/login')
            params = tests_utils.copy_form(response.context["form"])
            # POST ge prefiled from parameters
            response = client.post("/login", params)
            # the user should now being authenticated using username test@`provider`
            self.assert_logged(
                client, response, username=provider.build_username(settings.CAS_TEST_USER)
            )
            tickets.append((provider, ticket, client))

            # try to get a ticket
            response = client.get("/login", {'service': self.service})
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response["Location"].startswith("%s?ticket=" % self.service))
        return tickets

    def test_login_twice(self):
        """Test that user id db is used for the second login (cf coverage)"""
        self.test_login_post_provider()
        tickets = self.test_login_post_provider()
        # trying to authenticated while being already authenticated should redirect to /login
        for (provider, _, client) in tickets:
            response = client.get("/federate/%s" % provider.suffix)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response["Location"], "%s/login" % (
                'http://testserver' if django.VERSION < (1, 9) else ""
            ))

    @override_settings(CAS_FEDERATE=False)
    def test_auth_federate_false(self):
        """federated view should redirect to /login then CAS_FEDERATE is False"""
        provider = "example.com"
        client = Client()
        response = client.get("/federate/%s" % provider)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "%s/login" % (
            'http://testserver' if django.VERSION < (1, 9) else ""
        ))
        response = client.post("%s/federate/%s" % (
            'http://testserver' if django.VERSION < (1, 9) else "",
            provider
        ))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "%s/login" % (
            'http://testserver' if django.VERSION < (1, 9) else ""
        ))

    def test_auth_federate_errors(self):
        """
            The federated view should redirect to /login if the provider is unknown or not provided,
            try to fetch a new ticket if the provided ticket validation fail
            (network error or bad ticket), redirect to /login with a error message if identity
            provider CAS return a bad response (invalid XML document)
        """
        good_provider = "example.com"
        bad_provider = "exemple.fr"
        client = Client()
        response = client.get("/federate/%s" % bad_provider)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "%s/login" % (
            'http://testserver' if django.VERSION < (1, 9) else ""
        ))

        # test CAS not avaible
        response = client.get("/federate/%s" % good_provider, {'ticket': utils.gen_st()})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response["Location"],
            "%s/login?service=http%%3A%%2F%%2Ftestserver%%2Ffederate%%2F%s" % (
                models.FederatedIendityProvider.objects.get(suffix=good_provider).server_url,
                good_provider
            )
        )

        # test CAS avaible but bad ticket
        tests_utils.DummyCAS.run(
            ("http://testserver/federate/%s" % good_provider).encode("ascii"),
            utils.gen_st().encode("ascii"),
            settings.CAS_TEST_USER.encode("utf-8"),
            [],
            8080
        )
        response = client.get("/federate/%s" % good_provider, {'ticket': utils.gen_st()})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response["Location"],
            "%s/login?service=http%%3A%%2F%%2Ftestserver%%2Ffederate%%2F%s" % (
                models.FederatedIendityProvider.objects.get(suffix=good_provider).server_url,
                good_provider
            )
        )

        response = client.post("/federate")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "%s/login" % (
            'http://testserver' if django.VERSION < (1, 9) else ""
        ))

        # test CAS avaible but return a bad XML doc, should redirect to /login with a error message
        # use "example.net" as it is CASv3
        tests_utils.HttpParamsHandler.run(8082)
        response = client.get("/federate/%s" % "example.net", {'ticket': utils.gen_st()})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "%s/login" % (
            'http://testserver' if django.VERSION < (1, 9) else ""
        ))
        response = client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid response from your identity provider CAS", response.content)

    def test_auth_federate_slo(self):
        """test that SLO receive from backend CAS log out the users"""
        # get tickets and connected clients
        tickets = self.test_login_post_provider()
        for (provider, ticket, client) in tickets:
            # SLO for an unkown ticket should do nothing
            response = client.post(
                "/federate/%s" % provider.suffix,
                {'logoutRequest': utils.logout_request(utils.gen_st())}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b"ok")
            # Bad SLO format should do nothing
            response = client.post(
                "/federate/%s" % provider.suffix,
                {'logoutRequest': ""}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b"ok")
            # Bad SLO format should do nothing
            response = client.post(
                "/federate/%s" % provider.suffix,
                {'logoutRequest': "<root></root>"}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b"ok")
            response = client.get("/login")
            self.assert_logged(
                client, response, username=provider.build_username(settings.CAS_TEST_USER)
            )

            # SLO for a previously logged ticket should log out the user if CAS version is
            # 3 or 'CAS_2_SAML_1_0'
            response = client.post(
                "/federate/%s" % provider.suffix,
                {'logoutRequest': utils.logout_request(ticket)}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b"ok")

            response = client.get("/login")
            if provider.cas_protocol_version in {'3', 'CAS_2_SAML_1_0'}:  # support SLO
                self.assert_login_failed(client, response)
            else:
                self.assert_logged(
                    client, response, username=provider.build_username(settings.CAS_TEST_USER)
                )

    def test_federate_logout(self):
        """
            test the logout function: the user should be log out
            and redirected to his CAS logout page
        """
        # get tickets and connected clients, then follow normal logout
        tickets = self.test_login_post_provider()
        for (provider, _, client) in tickets:
            response = client.get("/logout")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(
                response["Location"],
                "%s/logout" % provider.server_url,
            )
            response = client.get("/login")
            self.assert_login_failed(client, response)

            # test if the user is already logged out
            response = client.get("/logout")
            # no redirection
            self.assertEqual(response.status_code, 200)
            self.assertTrue(
                (
                    b"You were already logged out from the Central Authentication Service."
                ) in response.content
            )

        tickets = self.test_login_post_provider()
        if django.VERSION >= (1, 8):
            # assume the username session variable has been tempered (should not happend)
            for (provider, _, client) in tickets:
                session = client.session
                session["username"] = settings.CAS_TEST_USER
                session.save()
                response = client.get("/logout")
                self.assertEqual(response.status_code, 200)
                response = client.get("/login")
                self.assert_login_failed(client, response)

    def test_remember_provider(self):
        """
            If the user check remember, next login should not offer the chose of the backend CAS
            and use the one store in the cookie
        """
        tickets = self.test_login_post_provider(remember=True)
        for (provider, _, client) in tickets:
            client.get("/logout")
            response = client.get("/login")
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response["Location"], "%s/federate/%s" % (
                'http://testserver' if django.VERSION < (1, 9) else "",
                provider.suffix
            ))

    def test_forget_provider(self):
        """Test the logout option to forget remembered provider"""
        tickets = self.test_login_post_provider(remember=True)
        for (provider, _, client) in tickets:
            self.assertIn("remember_provider", client.cookies)
            self.assertEqual(client.cookies["remember_provider"].value, provider.suffix)
            self.assertNotEqual(client.cookies["remember_provider"]["max-age"], 0)
            client.get("/logout?forget_provider=1")
            self.assertEqual(client.cookies["remember_provider"]["max-age"], 0)

    def test_renew(self):
        """
            Test authentication renewal with federation mode
        """
        tickets = self.test_login_post_provider()
        for (provider, _, client) in tickets:
            # Try to renew authentication(client already authenticated in test_login_post_provider
            response = client.get("/login?renew=true")
            # we should be redirected to the user CAS
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response["Location"], "%s/federate/%s?renew=true" % (
                'http://testserver' if django.VERSION < (1, 9) else "",
                provider.suffix
            ))

            response = client.get("/federate/%s?renew=true" % provider.suffix)
            self.assertEqual(response.status_code, 302)
            service_url = (
                "service=http%%3A%%2F%%2Ftestserver%%2Ffederate%%2F%s%%3Frenew%%3Dtrue"
            ) % provider.suffix
            self.assertIn(service_url, response["Location"])
            self.assertIn("renew=true", response["Location"])

            cas_port = int(provider.server_url.split(':')[-1])
            # let's generate a ticket
            ticket = utils.gen_st()
            # we lauch a dummy CAS server that only validate once for the service
            # http://testserver/federate/example.com?renew=true with `ticket`
            tests_utils.DummyCAS.run(
                ("http://testserver/federate/%s?renew=true" % provider.suffix).encode("ascii"),
                ticket.encode("ascii"),
                settings.CAS_TEST_USER.encode("utf8"),
                [],
                cas_port
            )
            # we normally provide a good ticket and should be redirected to /login as the ticket
            # get successfully validated again the dummy CAS
            response = client.get(
                '/federate/%s' % provider.suffix,
                {'ticket': ticket, 'renew': 'true'}
            )
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response["Location"], "%s/login?renew=true" % (
                'http://testserver' if django.VERSION < (1, 9) else ""
            ))
            # follow the redirect and try to get a ticket to see is it has renew set to True
            response = client.get("/login?renew=true&service=%s" % self.service)
            # we should get a page with a from with all widget hidden that auto POST to /login using
            # javascript. If javascript is disabled, a "connect" button is showed
            self.assertTrue(response.context['auto_submit'])
            self.assertEqual(response.context['post_url'], '/login')
            params = tests_utils.copy_form(response.context["form"])
            # POST get prefiled from parameters
            response = client.post("/login", params)
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response["Location"].startswith("%s?ticket=" % self.service))
            ticket_value = response["Location"].split('ticket=')[-1]
            ticket = models.ServiceTicket.objects.get(value=ticket_value)
            self.assertTrue(ticket.renew)

    def test_login_bad_ticket(self):
        """
            Try login with a bad ticket:
            login should fail and the main login page should be displayed to the user
        """
        provider = "example.com"
        # get a bare client
        client = Client()
        session = client.session
        session["federate_username"] = models.FederatedIendityProvider.build_username_from_suffix(
            settings.CAS_TEST_USER,
            provider
        )
        session["federate_ticket"] = utils.gen_st()
        if django.VERSION >= (1, 8):
            session.save()
            response = client.get("/login")
            # we should get a page with a from with all widget hidden that auto POST to /login using
            # javascript. If javascript is disabled, a "connect" button is showed
            self.assertTrue(response.context['auto_submit'])
            self.assertEqual(response.context['post_url'], '/login')
            params = tests_utils.copy_form(response.context["form"])
            # POST, as (username, ticket) are not valid, we should get the federate login page
            response = client.post("/login", params)
            self.assertEqual(response.status_code, 200)
            for provider in models.FederatedIendityProvider.objects.all():
                self.assertIn(
                    '<option value="%s">%s</option>' % (
                        provider.suffix,
                        provider.verbose_name
                    ),
                    response.content.decode("utf-8")
                )
            self.assertEqual(response.context['post_url'], '/federate')
