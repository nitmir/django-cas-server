# ⁻*- coding: utf-8 -*-
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
    def setup_service_patterns(self, proxy=False):
        """setting up service pattern"""
        # For general purpose testing
        self.service = "https://www.example.com"
        self.service_pattern = models.ServicePattern.objects.create(
            name="example",
            pattern="^https://www\.example\.com(/.*)?$",
            proxy=proxy,
        )
        models.ReplaceAttributName.objects.create(name="*", service_pattern=self.service_pattern)

        # For testing the restrict_users attributes
        self.service_restrict_user_fail = "https://restrict_user_fail.example.com"
        self.service_pattern_restrict_user_fail = models.ServicePattern.objects.create(
            name="restrict_user_fail",
            pattern="^https://restrict_user_fail\.example\.com(/.*)?$",
            restrict_users=True,
            proxy=proxy,
        )
        self.service_restrict_user_success = "https://restrict_user_success.example.com"
        self.service_pattern_restrict_user_success = models.ServicePattern.objects.create(
            name="restrict_user_success",
            pattern="^https://restrict_user_success\.example\.com(/.*)?$",
            restrict_users=True,
            proxy=proxy,
        )
        models.Username.objects.create(
            value=settings.CAS_TEST_USER,
            service_pattern=self.service_pattern_restrict_user_success
        )

        # For testing the user attributes filtering conditions
        self.service_filter_fail = "https://filter_fail.example.com"
        self.service_pattern_filter_fail = models.ServicePattern.objects.create(
            name="filter_fail",
            pattern="^https://filter_fail\.example\.com(/.*)?$",
            proxy=proxy,
        )
        models.FilterAttributValue.objects.create(
            attribut="right",
            pattern="^admin$",
            service_pattern=self.service_pattern_filter_fail
        )
        self.service_filter_fail_alt = "https://filter_fail_alt.example.com"
        self.service_pattern_filter_fail_alt = models.ServicePattern.objects.create(
            name="filter_fail_alt",
            pattern="^https://filter_fail_alt\.example\.com(/.*)?$",
            proxy=proxy,
        )
        models.FilterAttributValue.objects.create(
            attribut="nom",
            pattern="^toto$",
            service_pattern=self.service_pattern_filter_fail_alt
        )
        self.service_filter_success = "https://filter_success.example.com"
        self.service_pattern_filter_success = models.ServicePattern.objects.create(
            name="filter_success",
            pattern="^https://filter_success\.example\.com(/.*)?$",
            proxy=proxy,
        )
        models.FilterAttributValue.objects.create(
            attribut="email",
            pattern="^%s$" % re.escape(settings.CAS_TEST_ATTRIBUTES['email']),
            service_pattern=self.service_pattern_filter_success
        )

        # For testing the user_field attributes
        self.service_field_needed_fail = "https://field_needed_fail.example.com"
        self.service_pattern_field_needed_fail = models.ServicePattern.objects.create(
            name="field_needed_fail",
            pattern="^https://field_needed_fail\.example\.com(/.*)?$",
            user_field="uid",
            proxy=proxy,
        )
        self.service_field_needed_success = "https://field_needed_success.example.com"
        self.service_pattern_field_needed_success = models.ServicePattern.objects.create(
            name="field_needed_success",
            pattern="^https://field_needed_success\.example\.com(/.*)?$",
            user_field="alias",
            proxy=proxy,
        )
        self.service_field_needed_success_alt = "https://field_needed_success_alt.example.com"
        self.service_pattern_field_needed_success = models.ServicePattern.objects.create(
            name="field_needed_success_alt",
            pattern="^https://field_needed_success_alt\.example\.com(/.*)?$",
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
        attrs1 = set()
        for attr in attributes[0]:
            attrs1.add((attr.tag[len("http://www.yale.edu/tp/cas")+2:], attr.text))

        attributes = root.xpath("//cas:attribute", namespaces={'cas': "http://www.yale.edu/tp/cas"})
        self.assertEqual(len(attributes), len(attrs1))
        attrs2 = set()
        for attr in attributes:
            attrs2.add((attr.attrib['name'], attr.attrib['value']))
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
    def get_user(client):
        """return the user associated with an authenticated client"""
        return models.User.objects.get(
            username=settings.CAS_TEST_USER,
            session_key=client.session.session_key
        )
