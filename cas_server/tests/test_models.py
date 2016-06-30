"""Tests module for models"""
from cas_server.default_settings import settings

from django.test import TestCase
from django.test.utils import override_settings
from django.utils import timezone

from datetime import timedelta
from importlib import import_module

from cas_server import models
from cas_server import utils
from cas_server.tests.utils import get_auth_client
from cas_server.tests.mixin import UserModels, BaseServicePattern

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class UserTestCase(TestCase, UserModels):
    """tests for the user models"""
    def setUp(self):
        """Prepare the test context"""
        self.service = 'http://127.0.0.1:45678'
        self.service_pattern = models.ServicePattern.objects.create(
            name="localhost",
            pattern="^https?://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
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


@override_settings(CAS_AUTH_CLASS='cas_server.auth.TestAuthUser')
class TicketTestCase(TestCase, UserModels, BaseServicePattern):
    """tests for the tickets models"""
    def setUp(self):
        """Prepare the test context"""
        self.setup_service_patterns()
        self.service = 'http://127.0.0.1:45678'
        self.service_pattern = models.ServicePattern.objects.create(
            name="localhost",
            pattern="^https?://127\.0\.0\.1(:[0-9]+)?(/.*)?$",
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
        client = get_auth_client()
        user = self.get_user(client)
        self.get_ticket(user, models.ServiceTicket, self.service, self.service_pattern)
        self.get_ticket(
            user, models.ServiceTicket,
            self.service, self.service_pattern, validity_expired=True
        )
        (httpd, host, port) = utils.HttpParamsHandler.run()[0:3]
        service = "http://%s:%s" % (host, port)
        self.get_ticket(
            user, models.ServiceTicket,
            service, self.service_pattern, timeout_expired=True,
            validate=True, single_log_out=True
        )
        self.assertEqual(len(models.ServiceTicket.objects.all()), 3)
        models.ServiceTicket.clean_old_entries()
        params = httpd.PARAMS
        self.assertTrue(b'logoutRequest' in params and params[b'logoutRequest'])
        self.assertEqual(len(models.ServiceTicket.objects.all()), 1)
