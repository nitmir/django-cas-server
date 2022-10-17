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
"""Tests module for utils"""
import django
from django.test import TestCase, RequestFactory
from django.db import connection

import six
import warnings
import datetime

from cas_server import utils


class CheckPasswordCase(TestCase):
    """Tests for the utils function `utils.check_password`"""

    def setUp(self):
        """Generate random bytes string that will be used ass passwords"""
        self.password1 = utils.gen_saml_id()
        self.password2 = utils.gen_saml_id()
        if not isinstance(self.password1, bytes):  # pragma: no cover executed only in python3
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

    def test_plain_unicode(self):
        """test the plain auth method with unicode input"""
        self.assertTrue(
            utils.check_password(
                "plain",
                self.password1.decode("utf8"),
                self.password1.decode("utf8"),
                "utf8"
            )
        )
        self.assertFalse(
            utils.check_password(
                "plain",
                self.password1.decode("utf8"),
                self.password2.decode("utf8"),
                "utf8"
            )
        )

    def test_crypt(self):
        """test the crypt auth method"""
        salts = ["$6$UVVAQvrMyXMF3FF3", "aa"]
        hashed_password1 = []
        for salt in salts:
            if six.PY3:
                hashed_password1.append(
                    utils.crypt.crypt(
                        self.password1.decode("utf8"),
                        salt
                    ).encode("utf8")
                )
            else:
                hashed_password1.append(utils.crypt.crypt(self.password1, salt))

        for hp1 in hashed_password1:
            self.assertTrue(utils.check_password("crypt", self.password1, hp1, "utf8"))
            self.assertFalse(utils.check_password("crypt", self.password2, hp1, "utf8"))

        with self.assertRaises(ValueError):
            utils.check_password("crypt", self.password1, b"$truc$s$dsdsd", "utf8")

    def test_ldap_password_valid(self):
        """test the ldap auth method with all the schemes"""
        salt = b"UVVAQvrMyXMF3FF3"
        schemes_salt = [b"{SMD5}", b"{SSHA}", b"{SSHA256}", b"{SSHA384}", b"{SSHA512}"]
        schemes_nosalt = [b"{MD5}", b"{SHA}", b"{SHA256}", b"{SHA384}", b"{SHA512}"]
        hashed_password1 = []
        for scheme in schemes_salt:
            hashed_password1.append(
                utils.LdapHashUserPassword.hash(scheme, self.password1, salt, charset="utf8")
            )
        for scheme in schemes_nosalt:
            hashed_password1.append(
                utils.LdapHashUserPassword.hash(scheme, self.password1, charset="utf8")
            )
        hashed_password1.append(
            utils.LdapHashUserPassword.hash(
                b"{CRYPT}",
                self.password1,
                b"$6$UVVAQvrMyXMF3FF3",
                charset="utf8"
            )
        )
        for hp1 in hashed_password1:
            self.assertIsInstance(hp1, bytes)
            self.assertTrue(utils.check_password("ldap", self.password1, hp1, "utf8"))
            self.assertFalse(utils.check_password("ldap", self.password2, hp1, "utf8"))

    def test_ldap_password_fail(self):
        """test the ldap auth method with malformed hash or bad schemes"""
        salt = b"UVVAQvrMyXMF3FF3"
        schemes_salt = [b"{SMD5}", b"{SSHA}", b"{SSHA256}", b"{SSHA384}", b"{SSHA512}"]
        schemes_nosalt = [b"{MD5}", b"{SHA}", b"{SHA256}", b"{SHA384}", b"{SHA512}"]

        # first try to hash with bad parameters
        with self.assertRaises(utils.LdapHashUserPassword.BadScheme):
            utils.LdapHashUserPassword.hash(b"TOTO", self.password1)
        for scheme in schemes_nosalt:
            with self.assertRaises(utils.LdapHashUserPassword.BadScheme):
                utils.LdapHashUserPassword.hash(scheme, self.password1, salt)
        for scheme in schemes_salt:
            with self.assertRaises(utils.LdapHashUserPassword.BadScheme):
                utils.LdapHashUserPassword.hash(scheme, self.password1)
        with self.assertRaises(utils.LdapHashUserPassword.BadSalt):
            utils.LdapHashUserPassword.hash(b'{CRYPT}', self.password1, b"$truc$toto")

        # then try to check hash with bad hashes
        with self.assertRaises(utils.LdapHashUserPassword.BadHash):
            utils.check_password("ldap", self.password1, b"TOTOssdsdsd", "utf8")
        for scheme in schemes_salt:
            # bad length
            with self.assertRaises(utils.LdapHashUserPassword.BadHash):
                utils.check_password("ldap", self.password1, scheme + b"dG90b3E8ZHNkcw==", "utf8")
            # bad base64
            with self.assertRaises(utils.LdapHashUserPassword.BadHash):
                utils.check_password("ldap", self.password1, scheme + b"dG90b3E8ZHNkcw", "utf8")

    def test_hex(self):
        """test all the hex_HASH method: the hashed password is a simple hash of the password"""
        hashes = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
        hashed_password1 = []
        for hash_scheme in hashes:
            hashed_password1.append(
                (
                    "hex_%s" % hash_scheme,
                    getattr(utils.hashlib, hash_scheme)(self.password1).hexdigest()
                )
            )
        for (method, hp1) in hashed_password1:
            self.assertTrue(utils.check_password(method, self.password1, hp1, "utf8"))
            self.assertFalse(utils.check_password(method, self.password2, hp1, "utf8"))

    def test_bad_method(self):
        """try to check password with a bad method, should raise a ValueError"""
        with self.assertRaises(ValueError):
            utils.check_password("test", self.password1, b"$truc$s$dsdsd", "utf8")


class UtilsTestCase(TestCase):
    """tests for some little utils functions"""
    def test_import_attr(self):
        """
            test the import_attr function. Feeded with a dotted path string, it should
            import the dotted module and return that last componend of the dotted path
            (function, class or variable)
        """
        with self.assertRaises(ImportError):
            utils.import_attr('toto.titi.tutu')
        with self.assertRaises(AttributeError):
            utils.import_attr('cas_server.utils.toto')
        with self.assertRaises(ValueError):
            utils.import_attr('toto')
        if django.VERSION < (3, 2):
            self.assertEqual(
                utils.import_attr('cas_server.default_app_config'),
                'cas_server.apps.CasAppConfig'
            )
        self.assertEqual(utils.import_attr(utils), utils)

    def test_update_url(self):
        """
            test the update_url function. Given an url with possible GET parameter and a dict
            the function build a url with GET parameters updated by the dictionnary
        """
        url1 = utils.update_url(u"https://www.example.com?toto=1", {u"tata": u"2"})
        url2 = utils.update_url(b"https://www.example.com?toto=1", {b"tata": b"2"})
        self.assertEqual(url1, u"https://www.example.com?tata=2&toto=1")
        self.assertEqual(url2, u"https://www.example.com?tata=2&toto=1")

        url3 = utils.update_url(u"https://www.example.com?toto=1", {u"toto": u"2"})
        self.assertEqual(url3, u"https://www.example.com?toto=2")

    def test_crypt_salt_is_valid(self):
        """test the function crypt_salt_is_valid who test if a crypt salt is valid"""
        self.assertFalse(utils.crypt_salt_is_valid(""))  # len 0
        self.assertFalse(utils.crypt_salt_is_valid("a"))  # len 1
        self.assertFalse(utils.crypt_salt_is_valid("$$"))  # start with $ followed by $
        self.assertFalse(utils.crypt_salt_is_valid("$toto"))  # start with $ but no secondary $
        self.assertFalse(utils.crypt_salt_is_valid("$toto$toto"))  # algorithm toto not known

    def test_get_current_url(self):
        """test the function get_current_url"""
        factory = RequestFactory()
        request = factory.get('/truc/muche?test=1')
        self.assertEqual(utils.get_current_url(request), 'http://testserver/truc/muche?test=1')
        self.assertEqual(
            utils.get_current_url(request, ignore_params={'test'}),
            'http://testserver/truc/muche'
        )

    def test_get_tuple(self):
        """test the function get_tuple"""
        test_tuple = (1, 2, 3)
        for index, value in enumerate(test_tuple):
            self.assertEqual(utils.get_tuple(test_tuple, index), value)
        self.assertEqual(utils.get_tuple(test_tuple, 3), None)
        self.assertEqual(utils.get_tuple(test_tuple, 3, 'toto'), 'toto')
        self.assertEqual(utils.get_tuple(None, 3), None)

    def test_last_version(self):
        """
            test the function last_version. An internet connection is needed, if you do not have
            one, this test will fail and you should ignore it.
        """
        try:
            # first check if pypi is available
            utils.requests.get("https://pypi.org/simple/django-cas-server/")
        except utils.requests.exceptions.RequestException:
            warnings.warn(
                (
                    "Pypi seems not available, perhaps you do not have internet access. "
                    "Consequently, the test cas_server.tests.test_utils.UtilsTestCase.test_last_"
                    "version is ignored"
                ),
                RuntimeWarning
            )
        else:
            version = utils.last_version()
            self.assertIsInstance(version, six.text_type)
            self.assertEqual(len(version.split('.')), 3)

            # version is cached 24h so calling it a second time should return the save value
            self.assertEqual(version, utils.last_version())

    def test_dictfetchall(self):
        """test the function dictfetchall"""
        with connection.cursor() as curs:
            curs.execute("SELECT * FROM django_migrations")
            results = utils.dictfetchall(curs)
            self.assertIsInstance(results, list)
            self.assertTrue(len(results) > 0)
            for result in results:
                self.assertIsInstance(result, dict)
                self.assertIn('applied', result)
                self.assertIsInstance(result['applied'], datetime.datetime)

    def test_regexpr_validator(self):
        """test the function regexpr_validator"""
        utils.regexpr_validator("^a$")
        with self.assertRaises(utils.ValidationError):
            utils.regexpr_validator("[")
