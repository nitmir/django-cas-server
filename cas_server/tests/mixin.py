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
"""Some mixin classes for tests"""
from cas_server.default_settings import settings
from django.utils import timezone

import re
from lxml import etree
from datetime import timedelta

from cas_server import models
from cas_server.tests.utils import get_auth_client


class BaseServicePattern(object):
    """Mixing for setting up service pattern for testing"""
    @classmethod
    def setup_service_patterns(cls, proxy=False):
        """setting up service pattern"""
        # For general purpose testing
        cls.service = "https://www.example.com"
        cls.service_pattern = models.ServicePattern.objects.create(
            name="example",
            pattern=r"^https://www\.example\.com(/.*)?$",
            proxy=proxy,
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=cls.service_pattern)

        # For testing the restrict_users attributes
        cls.service_restrict_user_fail = "https://restrict_user_fail.example.com"
        cls.service_pattern_restrict_user_fail = models.ServicePattern.objects.create(
            name="restrict_user_fail",
            pattern=r"^https://restrict_user_fail\.example\.com(/.*)?$",
            restrict_users=True,
            proxy=proxy,
        )
        cls.service_restrict_user_success = "https://restrict_user_success.example.com"
        cls.service_pattern_restrict_user_success = models.ServicePattern.objects.create(
            name="restrict_user_success",
            pattern=r"^https://restrict_user_success\.example\.com(/.*)?$",
            restrict_users=True,
            proxy=proxy,
        )
        models.Username.objects.create(
            value=settings.CAS_TEST_USER,
            service_pattern=cls.service_pattern_restrict_user_success
        )

        # For testing the user attributes filtering conditions
        cls.service_filter_fail = "https://filter_fail.example.com"
        cls.service_pattern_filter_fail = models.ServicePattern.objects.create(
            name="filter_fail",
            pattern=r"^https://filter_fail\.example\.com(/.*)?$",
            proxy=proxy,
        )
        models.FilterAttributValue.objects.create(
            attribut="right",
            pattern="^admin$",
            service_pattern=cls.service_pattern_filter_fail
        )
        cls.service_filter_fail_alt = "https://filter_fail_alt.example.com"
        cls.service_pattern_filter_fail_alt = models.ServicePattern.objects.create(
            name="filter_fail_alt",
            pattern=r"^https://filter_fail_alt\.example\.com(/.*)?$",
            proxy=proxy,
        )
        models.FilterAttributValue.objects.create(
            attribut="nom",
            pattern="^toto$",
            service_pattern=cls.service_pattern_filter_fail_alt
        )
        cls.service_filter_success = "https://filter_success.example.com"
        cls.service_pattern_filter_success = models.ServicePattern.objects.create(
            name="filter_success",
            pattern=r"^https://filter_success\.example\.com(/.*)?$",
            proxy=proxy,
        )
        models.FilterAttributValue.objects.create(
            attribut="email",
            pattern="^%s$" % re.escape(settings.CAS_TEST_ATTRIBUTES['email']),
            service_pattern=cls.service_pattern_filter_success
        )

        # For testing the user_field attributes
        cls.service_field_needed_fail = "https://field_needed_fail.example.com"
        cls.service_pattern_field_needed_fail = models.ServicePattern.objects.create(
            name="field_needed_fail",
            pattern=r"^https://field_needed_fail\.example\.com(/.*)?$",
            user_field="uid",
            proxy=proxy,
        )
        cls.service_field_needed_success = "https://field_needed_success.example.com"
        cls.service_pattern_field_needed_success = models.ServicePattern.objects.create(
            name="field_needed_success",
            pattern=r"^https://field_needed_success\.example\.com(/.*)?$",
            user_field="alias",
            proxy=proxy,
        )
        cls.service_field_needed_success_alt = "https://field_needed_success_alt.example.com"
        cls.service_pattern_field_needed_success = models.ServicePattern.objects.create(
            name="field_needed_success_alt",
            pattern=r"^https://field_needed_success_alt\.example\.com(/.*)?$",
            user_field="nom",
            proxy=proxy,
        )


class XmlContent(object):
    """Mixin for test on CAS XML responses"""
    def assert_error(self, response, code, text=None):
        """Assert a validation error"""
        self.assertEqual(response.status_code, 200)
        root = etree.fromstring(response.content)
        error = root.xpath(
            "//cas:authenticationFailure",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(error), 1)
        self.assertEqual(error[0].attrib['code'], code)
        if text is not None:
            self.assertEqual(error[0].text, text)

    def assert_success(self, response, username, original_attributes):
        """assert a ticket validation success"""
        self.assertEqual(response.status_code, 200)

        root = etree.fromstring(response.content)
        sucess = root.xpath(
            "//cas:authenticationSuccess",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertTrue(sucess)

        users = root.xpath("//cas:user", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].text, username)

        attributes = root.xpath(
            "//cas:attributes",
            namespaces={'cas': "http://www.yale.edu/tp/cas"}
        )
        self.assertEqual(len(attributes), 1)
        ignore_attrs = {
            "authenticationDate", "longTermAuthenticationRequestTokenUsed", "isFromNewLogin"
        }
        ignored_attrs = 0
        attrs1 = set()
        for attr in attributes[0]:
            name = attr.tag[len("http://www.yale.edu/tp/cas")+2:]
            if name not in ignore_attrs:
                attrs1.add((name, attr.text))
            else:
                ignored_attrs += 1

        attributes = root.xpath("//cas:attribute", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(attributes), len(attrs1) + ignored_attrs)
        attrs2 = set()
        for attr in attributes:
            name = attr.attrib['name']
            if name not in ignore_attrs:
                attrs2.add((name, attr.attrib['value']))
        original = set()
        for key, value in original_attributes.items():
            if isinstance(value, list):
                for sub_value in value:
                    original.add((key, sub_value))
            else:
                original.add((key, value))
        self.assertEqual(attrs1, attrs2)
        self.assertEqual(attrs1, original)

        return root


class UserModels(object):
    """Mixin for test on CAS user models"""
    @staticmethod
    def expire_user():
        """return an expired user"""
        client = get_auth_client()

        new_date = timezone.now() - timedelta(seconds=(settings.SESSION_COOKIE_AGE + 600))
        models.User.objects.filter(
            username=settings.CAS_TEST_USER,
            session_key=client.session.session_key
        ).update(date=new_date)
        return client

    @staticmethod
    def tgt_expired_user(sec):
        """return a user logged since sec seconds"""
        client = get_auth_client()
        new_date = timezone.now() - timedelta(seconds=(sec))
        models.User.objects.filter(
            username=settings.CAS_TEST_USER,
            session_key=client.session.session_key
        ).update(last_login=new_date)
        return client

    @staticmethod
    def get_user(client):
        """return the user associated with an authenticated client"""
        return models.User.objects.get(
            username=settings.CAS_TEST_USER,
            session_key=client.session.session_key
        )


class CanLogin(object):
    """Assertion about login"""
    def assert_logged(
        self, client, response, warn=False,
        code=200, username=settings.CAS_TEST_USER
    ):
        """Assertions testing that client is well authenticated"""
        self.assertEqual(response.status_code, code)
        # this message is displayed to the user upon successful authentication
        self.assertIn(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ),
            response.content
        )
        # these session variables a set if usccessfully authenticated
        self.assertEqual(client.session["username"], username)
        self.assertIs(client.session["warn"], warn)
        self.assertIs(client.session["authenticated"], True)

        # on successfull authentication, a corresponding user object is created
        self.assertTrue(
            models.User.objects.get(
                username=username,
                session_key=client.session.session_key
            )
        )

    def assert_login_failed(self, client, response, code=200):
        """Assertions testing a failed login attempt"""
        self.assertEqual(response.status_code, code)
        # this message is displayed to the user upon successful authentication, so it should not
        # appear
        self.assertNotIn(
            (
                b"You have successfully logged into "
                b"the Central Authentication Service"
            ),
            response.content
        )

        # if authentication has failed, these session variables should not be set
        self.assertTrue(client.session.get("username") is None)
        self.assertTrue(client.session.get("warn") is None)
        self.assertTrue(client.session.get("authenticated") is None)


class FederatedIendityProviderModel(object):
    """Mixin for test classes using  the FederatedIendityProvider model"""
    @staticmethod
    def setup_federated_identity_provider(providers):
        """setting up federated identity providers"""
        for suffix, (server_url, cas_protocol_version, verbose_name) in providers.items():
            models.FederatedIendityProvider.objects.create(
                suffix=suffix,
                server_url=server_url,
                cas_protocol_version=cas_protocol_version,
                verbose_name=verbose_name
            )
