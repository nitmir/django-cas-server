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
# (c) 2015-2016 Valentin Samir
"""Some authentication classes for the CAS"""
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone

from datetime import timedelta
try:  # pragma: no cover
    import MySQLdb
    import MySQLdb.cursors
    from utils import check_password
except ImportError:
    MySQLdb = None

from .models import FederatedUser


class AuthUser(object):
    """
        Authentication base class

        :param unicode username: A username, stored in the :attr:`username` class attribute.
    """

    #: username used to instanciate the current object
    username = None

    def __init__(self, username):
        self.username = username

    def test_password(self, password):
        """
            Tests ``password`` agains the user password.

            :raises NotImplementedError: always. The method need to be implemented by subclasses
        """
        raise NotImplementedError()

    def attributs(self):
        """
            The user attributes.

            raises NotImplementedError: always. The method need to be implemented by subclasses
        """
        raise NotImplementedError()


class DummyAuthUser(AuthUser):  # pragma: no cover
    """
        A Dummy authentication class. Authentication always fails

        :param unicode username: A username, stored in the :attr:`username<AuthUser.username>`
            class attribute. There is no valid value for this attribute here.
    """

    def test_password(self, password):
        """
            Tests ``password`` agains the user password.

            :param unicode password: a clear text password as submited by the user.
            :return: always ``False``
            :rtype: bool
        """
        return False

    def attributs(self):
        """
            The user attributes.

            :return: en empty :class:`dict`.
            :rtype: dict
        """
        return {}


class TestAuthUser(AuthUser):
    """
        A test authentication class only working for one unique user.

        :param unicode username: A username, stored in the :attr:`username<AuthUser.username>`
            class attribute. The uniq valid value is ``settings.CAS_TEST_USER``.
    """

    def test_password(self, password):
        """
            Tests ``password`` agains the user password.

            :param unicode password: a clear text password as submited by the user.
            :return: ``True`` if :attr:`username<AuthUser.username>` is valid and
                ``password`` is equal to ``settings.CAS_TEST_PASSWORD``, ``False`` otherwise.
            :rtype: bool
        """
        return self.username == settings.CAS_TEST_USER and password == settings.CAS_TEST_PASSWORD

    def attributs(self):
        """
            The user attributes.

            :return: the ``settings.CAS_TEST_ATTRIBUTES`` :class:`dict` if
                :attr:`username<AuthUser.username>` is valid, an empty :class:`dict` otherwise.
            :rtype: dict
        """
        if self.username == settings.CAS_TEST_USER:
            return settings.CAS_TEST_ATTRIBUTES
        else:  # pragma: no cover (should not happen)
            return {}


class MysqlAuthUser(AuthUser):  # pragma: no cover
    """
        A mysql authentication class: authentication user agains a mysql database

        :param unicode username: A username, stored in the :attr:`username<AuthUser.username>`
            class attribute. Valid value are fetched from the MySQL database set with
            ``settings.CAS_SQL_*`` settings parameters using the query
            ``settings.CAS_SQL_USER_QUERY``.
    """
    #: Mysql user attributes as a :class:`dict` if the username is found in the database.
    user = None

    def __init__(self, username):
        # see the connect function at
        # http://mysql-python.sourceforge.net/MySQLdb.html#functions-and-attributes
        # for possible mysql config parameters.
        mysql_config = {
            "user": settings.CAS_SQL_USERNAME,
            "passwd": settings.CAS_SQL_PASSWORD,
            "db": settings.CAS_SQL_DBNAME,
            "host": settings.CAS_SQL_HOST,
            "charset": settings.CAS_SQL_DBCHARSET,
            "cursorclass": MySQLdb.cursors.DictCursor
        }
        if not MySQLdb:
            raise RuntimeError("Please install MySQLdb before using the MysqlAuthUser backend")
        conn = MySQLdb.connect(**mysql_config)
        curs = conn.cursor()
        if curs.execute(settings.CAS_SQL_USER_QUERY, (username,)) == 1:
            self.user = curs.fetchone()
            super(MysqlAuthUser, self).__init__(self.user['username'])
        else:
            super(MysqlAuthUser, self).__init__(username)

    def test_password(self, password):
        """
            Tests ``password`` agains the user password.

            :param unicode password: a clear text password as submited by the user.
            :return: ``True`` if :attr:`username<AuthUser.username>` is valid and ``password`` is
                correct, ``False`` otherwise.
            :rtype: bool
        """
        if self.user:
            return check_password(
                settings.CAS_SQL_PASSWORD_CHECK,
                password,
                self.user["password"],
                settings.CAS_SQL_DBCHARSET
            )
        else:
            return False

    def attributs(self):
        """
            The user attributes.

            :return: a :class:`dict` with the user attributes. Attributes may be :func:`unicode`
                or :class:`list` of :func:`unicode`. If the user do not exists, the returned
                :class:`dict` is empty.
            :rtype: dict
        """
        if self.user:
            return self.user
        else:
            return {}


class DjangoAuthUser(AuthUser):  # pragma: no cover
    """
        A django auth class: authenticate user agains django internal users

        :param unicode username: A username, stored in the :attr:`username<AuthUser.username>`
            class attribute. Valid value are usernames of django internal users.
    """
    #: a django user object if the username is found. The user model is retreived
    #: using :func:`django.contrib.auth.get_user_model`.
    user = None

    def __init__(self, username):
        User = get_user_model()
        try:
            self.user = User.objects.get(username=username)
        except User.DoesNotExist:
            pass
        super(DjangoAuthUser, self).__init__(username)

    def test_password(self, password):
        """
            Tests ``password`` agains the user password.

            :param unicode password: a clear text password as submited by the user.
            :return: ``True`` if :attr:`user` is valid and ``password`` is
                correct, ``False`` otherwise.
            :rtype: bool
        """
        if self.user:
            return self.user.check_password(password)
        else:
            return False

    def attributs(self):
        """
            The user attributes, defined as the fields on the :attr:`user` object.

            :return: a :class:`dict` with the :attr:`user` object fields. Attributes may be
                If the user do not exists, the returned :class:`dict` is empty.
            :rtype: dict
        """
        if self.user:
            attr = {}
            for field in self.user._meta.fields:
                attr[field.attname] = getattr(self.user, field.attname)
            return attr
        else:
            return {}


class CASFederateAuth(AuthUser):
    """
        Authentication class used then CAS_FEDERATE is True

        :param unicode username: A username, stored in the :attr:`username<AuthUser.username>`
            class attribute. Valid value are usernames of
            :class:`FederatedUser<cas_server.models.FederatedUser>` object.
            :class:`FederatedUser<cas_server.models.FederatedUser>` object are created on CAS
            backends successful ticket validation.
    """
    #: a :class`FederatedUser<cas_server.models.FederatedUser>` object if ``username`` is found.
    user = None

    def __init__(self, username):
        try:
            self.user = FederatedUser.get_from_federated_username(username)
            super(CASFederateAuth, self).__init__(
                self.user.federated_username
            )
        except FederatedUser.DoesNotExist:
            super(CASFederateAuth, self).__init__(username)

    def test_password(self, ticket):
        """
            Tests ``password`` agains the user password.

            :param unicode password: The CAS tickets just used to validate the user authentication
                against its CAS backend.
            :return: ``True`` if :attr:`user` is valid and ``password`` is
                a ticket validated less than ``settings.CAS_TICKET_VALIDITY`` secondes and has not
                being previously used for authenticated this
                :class:`FederatedUser<cas_server.models.FederatedUser>`. ``False`` otherwise.
            :rtype: bool
        """
        if not self.user or not self.user.ticket:
            return False
        else:
            return (
                ticket == self.user.ticket and
                self.user.last_update >
                (timezone.now() - timedelta(seconds=settings.CAS_TICKET_VALIDITY))
            )

    def attributs(self):
        """
            The user attributes, as returned by the CAS backend.

            :return: :obj:`FederatedUser.attributs<cas_server.models.FederatedUser.attributs>`.
                If the user do not exists, the returned :class:`dict` is empty.
            :rtype: dict
        """
        if not self.user:  # pragma: no cover (should not happen)
            return {}
        else:
            return self.user.attributs
