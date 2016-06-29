from django.test import TestCase

import six

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
