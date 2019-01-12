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
"""Tests module for models"""
from cas_server.default_settings import settings

import django
from django.test import TestCase, Client
from django.test.utils import override_settings
from django.utils import timezone
from django.core import mail

import mock
from datetime import timedelta
from importlib import import_module

from cas_server import models, utils
from cas_server.tests.utils import get_auth_client, HttpParamsHandler
from cas_server.tests.mixin import UserModels, BaseServicePattern, FederatedIendityProviderModel
from cas_server.tests.test_federate import PROVIDERS

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore


class FederatedUserTestCase(TestCase, UserModels, FederatedIendityProviderModel):
    """test for the federated user model"""
    def setUp(self):
        """Prepare the test context"""
        self.setup_federated_identity_provider(PROVIDERS)

    def test_clean_old_entries(self):
        """tests for clean_old_entries that should delete federated user no longer used"""
        client = Client()
        client.get("/login")
        provider = models.FederatedIendityProvider.objects.get(suffix="example.com")
        models.FederatedUser.objects.create(
            username="test1", provider=provider, attributs={}, ticket=""
        )
        models.FederatedUser.objects.create(
            username="test2", provider=provider, attributs={}, ticket=""
        )
        models.FederatedUser.objects.all().update(
            last_update=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_TIMEOUT + 10))
        )
        models.FederatedUser.objects.create(
            username="test3", provider=provider, attributs={}, ticket=""
        )
        models.User.objects.create(
            username="test1@example.com", session_key=client.session.session_key
        )
        self.assertEqual(len(models.FederatedUser.objects.all()), 3)
        models.FederatedUser.clean_old_entries()
        self.assertEqual(len(models.FederatedUser.objects.all()), 2)
        with self.assertRaises(models.FederatedUser.DoesNotExist):
            models.FederatedUser.objects.get(username="test2")

    def test_json_attributes(self):
        """test the json storage of ``atrributs`` in ``_attributs``"""
        provider = models.FederatedIendityProvider.objects.get(suffix="example.com")
        user = models.FederatedUser.objects.create(
            username=settings.CAS_TEST_USER,
            provider=provider,
            attributs=settings.CAS_TEST_ATTRIBUTES,
            ticket=""
        )
        self.assertEqual(utils.json_encode(settings.CAS_TEST_ATTRIBUTES), user._attributs)
        user.delete()
        user = models.FederatedUser.objects.create(
            username=settings.CAS_TEST_USER,
            provider=provider,
            ticket=""
        )
        self.assertIsNone(user._attributs)
        self.assertIsNone(user.attributs)


class FederateSLOTestCase(TestCase, UserModels):
    """test for the federated SLO model"""
    def test_clean_deleted_sessions(self):
        """
            tests for clean_deleted_sessions that should delete object for which matching session
            do not exists anymore
        """
        if django.VERSION >= (1, 8):
            client1 = Client()
            client2 = Client()
            client1.get("/login")
            client2.get("/login")
            session = client2.session
            session['authenticated'] = True
            session.save()
            models.FederateSLO.objects.create(
                username="test1@example.com",
                session_key=client1.session.session_key,
                ticket=utils.gen_st()
            )
            models.FederateSLO.objects.create(
                username="test2@example.com",
                session_key=client2.session.session_key,
                ticket=utils.gen_st()
            )
            self.assertEqual(len(models.FederateSLO.objects.all()), 2)
            models.FederateSLO.clean_deleted_sessions()
            self.assertEqual(len(models.FederateSLO.objects.all()), 1)
            with self.assertRaises(models.FederateSLO.DoesNotExist):
                models.FederateSLO.objects.get(username="test1@example.com")


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class UserAttributesTestCase(TestCase, UserModels):
    """test for the user attributes cache model"""
    def test_clean_old_entries(self):
        """test the clean_old_entries methode"""
        client = get_auth_client()
        user = self.get_user(client)
        models.UserAttributes.objects.create(username=settings.CAS_TEST_USER)

        # test that attribute cache is removed for non existant users
        self.assertEqual(len(models.UserAttributes.objects.all()), 1)
        models.UserAttributes.clean_old_entries()
        self.assertEqual(len(models.UserAttributes.objects.all()), 1)
        user.delete()
        models.UserAttributes.clean_old_entries()
        self.assertEqual(len(models.UserAttributes.objects.all()), 0)


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class UserTestCase(TestCase, UserModels):
    """tests for the user models"""
    def setUp(self):
        """Prepare the test context"""
        self.service = 'http://127.0.0.1:45678'
        self.service_pattern = models.ServicePattern.objects.create(
            name="localhost",
            pattern=r"^https?://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
            single_log_out=True
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

    def test_clean_old_entries(self):
        """test clean_old_entries"""
        # get an authenticated client
        client = self.expire_user()
        # assert the user exists before being cleaned
        self.assertEqual(len(models.User.objects.all()), 1)
        # assert the last activity date is before the expiry date
        self.assertTrue(
            self.get_user(client).date < (
                timezone.now() - timedelta(seconds=settings.SESSION_COOKIE_AGE)
            )
        )
        # delete old inactive users
        models.User.clean_old_entries()
        # assert the user has being well delete
        self.assertEqual(len(models.User.objects.all()), 0)

    @override_settings(CAS_TGT_VALIDITY=3600)
    def test_clean_old_entries_tgt_expired(self):
        """test clean_old_entiers with CAS_TGT_VALIDITY set"""
        # get an authenticated client
        client = self.tgt_expired_user(settings.CAS_TGT_VALIDITY + 60)
        # assert the user exists before being cleaned
        self.assertEqual(len(models.User.objects.all()), 1)
        # assert the last lofin date is before the expiry date
        self.assertTrue(
            self.get_user(client).last_login < (
                timezone.now() - timedelta(seconds=settings.CAS_TGT_VALIDITY)
            )
        )
        # delete old inactive users
        models.User.clean_old_entries()
        # assert the user has being well delete
        self.assertEqual(len(models.User.objects.all()), 0)

    def test_clean_deleted_sessions(self):
        """test clean_deleted_sessions"""
        # get an authenticated client
        client1 = get_auth_client()
        client2 = get_auth_client()
        # generate a ticket to fire SLO during user cleaning (SLO should fail a nothing listen
        # on self.service)
        ticket = self.get_user(client1).get_ticket(
            models.ServiceTicket,
            self.service,
            self.service_pattern,
            renew=False
        )
        ticket.validate = True
        ticket.save()
        # simulated expired session being garbage collected for client1
        session = SessionStore(session_key=client1.session.session_key)
        session.flush()
        # assert the user exists before being cleaned
        self.assertTrue(self.get_user(client1))
        self.assertTrue(self.get_user(client2))
        self.assertEqual(len(models.User.objects.all()), 2)
        # session has being remove so the user of client1 is no longer authenticated
        self.assertFalse(client1.session.get("authenticated"))
        # the user a client2 should still be authenticated
        self.assertTrue(client2.session.get("authenticated"))
        # the user should be deleted
        models.User.clean_deleted_sessions()
        # assert the user with expired sessions has being well deleted but the other remain
        self.assertEqual(len(models.User.objects.all()), 1)
        self.assertFalse(models.ServiceTicket.objects.all())
        self.assertTrue(client2.session.get("authenticated"))

    @override_settings(CAS_AUTH_CLASS='cas_server.tests.auth.TestCachedAttributesAuthUser')
    def test_cached_attributs(self):
        """
            Test gettting user attributes from cache for auth method that do not support direct
            fetch (link the ldap bind auth methode)
        """
        client = get_auth_client()
        user = self.get_user(client)
        # if no cache is defined, the attributes are empty
        self.assertEqual(user.attributs, {})
        user_attr = models.UserAttributes.objects.create(username=settings.CAS_TEST_USER)
        # if a cache is defined but without atrributes, also empty
        self.assertEqual(user.attributs, {})
        user_attr.attributs = settings.CAS_TEST_ATTRIBUTES
        user_attr.save()
        # attributes are what is found in the cache
        self.assertEqual(user.attributs, settings.CAS_TEST_ATTRIBUTES)


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class TicketTestCase(TestCase, UserModels, BaseServicePattern):
    """tests for the tickets models"""
    def setUp(self):
        """Prepare the test context"""
        self.setup_service_patterns()
        self.service = 'http://127.0.0.1:45678'
        self.service_pattern = models.ServicePattern.objects.create(
            name="localhost",
            pattern=r"^https?://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
            single_log_out=True
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

    @staticmethod
    def get_ticket(
        user,
        ticket_class,
        service,
        service_pattern,
        renew=False,
        validate=False,
        validity_expired=False,
        timeout_expired=False,
        single_log_out=False,
    ):
        """Return a ticket"""
        ticket = user.get_ticket(ticket_class, service, service_pattern, renew)
        ticket.validate = validate
        ticket.single_log_out = single_log_out
        if validity_expired:
            ticket.creation = min(
                ticket.creation,
                (timezone.now() - timedelta(seconds=(ticket_class.VALIDITY + 10)))
            )
        if timeout_expired:
            ticket.creation = min(
                ticket.creation,
                (timezone.now() - timedelta(seconds=(ticket_class.TIMEOUT + 10)))
            )
        ticket.save()
        return ticket

    def test_clean_old_service_ticket(self):
        """test tickets clean_old_entries"""
        # ge an authenticated client
        client = get_auth_client()
        # get the user associated to the client
        user = self.get_user(client)
        # generate a ticket for that client, waiting for validation
        self.get_ticket(user, models.ServiceTicket, self.service, self.service_pattern)
        # generate another ticket for those validation time has expired
        self.get_ticket(
            user, models.ServiceTicket,
            self.service, self.service_pattern, validity_expired=True
        )
        (httpd, host, port) = HttpParamsHandler.run()[0:3]
        service = "http://%s:%s" % (host, port)
        # generate a ticket with SLO having timeout reach
        self.get_ticket(
            user, models.ServiceTicket,
            service, self.service_pattern, timeout_expired=True,
            validate=True, single_log_out=True
        )
        # there should be 3 tickets in the db
        self.assertEqual(len(models.ServiceTicket.objects.all()), 3)
        # we call the clean_old_entries method that should delete validated non SLO ticket and
        # expired non validated ticket and send SLO for SLO expired ticket before deleting then
        models.ServiceTicket.clean_old_entries()
        params = httpd.PARAMS
        # we successfully got a SLO request
        self.assertTrue(b'logoutRequest' in params and params[b'logoutRequest'])
        # only 1 ticket remain in the db
        self.assertEqual(len(models.ServiceTicket.objects.all()), 1)

    def test_json_attributes(self):
        """test the json storage of ``atrributs`` in ``_attributs``"""
        # ge an authenticated client
        client = get_auth_client()
        # get the user associated to the client
        user = self.get_user(client)
        ticket = models.ServiceTicket.objects.create(
            user=user,
            service=self.service,
            attributs=settings.CAS_TEST_ATTRIBUTES,
            service_pattern=self.service_pattern
        )
        self.assertEqual(utils.json_encode(settings.CAS_TEST_ATTRIBUTES), ticket._attributs)
        ticket.delete()
        ticket = models.ServiceTicket.objects.create(
            user=user,
            service=self.service,
            service_pattern=self.service_pattern
        )
        self.assertIsNone(ticket._attributs)
        self.assertIsNone(ticket.attributs)


@mock.patch("cas_server.utils.last_version", lambda: "1.2.3")
@override_settings(ADMINS=[("Ano Nymous", "ano.nymous@example.net")])
@override_settings(CAS_NEW_VERSION_EMAIL_WARNING=True)
class NewVersionWarningTestCase(TestCase):
    """tests for the new version warning model"""

    @mock.patch("cas_server.models.VERSION", "0.1.2")
    def test_send_mails(self):
        """test the send_mails method with ADMINS and a new version available"""
        models.NewVersionWarning.send_mails()

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(
            mail.outbox[0].subject,
            '%sA new version of django-cas-server is available' % settings.EMAIL_SUBJECT_PREFIX
        )

        models.NewVersionWarning.send_mails()
        self.assertEqual(len(mail.outbox), 1)

    @mock.patch("cas_server.models.VERSION", "1.2.3")
    def test_send_mails_same_version(self):
        """test the send_mails method with with current version being the last"""
        models.NewVersionWarning.objects.create(version="0.1.2")
        models.NewVersionWarning.send_mails()
        self.assertEqual(len(mail.outbox), 0)

    @override_settings(ADMINS=[])
    def test_send_mails_no_admins(self):
        """test the send_mails method without ADMINS"""
        models.NewVersionWarning.send_mails()
        self.assertEqual(len(mail.outbox), 0)

    @override_settings(CAS_NEW_VERSION_EMAIL_WARNING=False)
    def test_send_mails_disabled(self):
        """test the send_mails method if disabled"""
        models.NewVersionWarning.send_mails()
        self.assertEqual(len(mail.outbox), 0)
