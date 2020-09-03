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
from django.db import connections, DatabaseError

import warnings
from datetime import timedelta
from six.moves import range
try:  # pragma: no cover
    import MySQLdb
    import MySQLdb.cursors
except ImportError:
    MySQLdb = None


try:  # pragma: no cover
    import ldap3
    import ldap3.core.exceptions
except ImportError:
    ldap3 = None

from .models import FederatedUser, UserAttributes
from .utils import check_password, dictfetchall


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
            Tests ``password`` against the user-supplied password.

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
            Tests ``password`` against the user-supplied password.

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
            Tests ``password`` against the user-supplied password.

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


class DBAuthUser(AuthUser):  # pragma: no cover
    """base class for databate based auth classes"""
    #: DB user attributes as a :class:`dict` if the username is found in the database.
    user = None

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


class MysqlAuthUser(DBAuthUser):  # pragma: no cover
    """
        DEPRECATED, use :class:`SqlAuthUser` instead.

        A mysql authentication class: authenticate user against a mysql database

        :param unicode username: A username, stored in the :attr:`username<AuthUser.username>`
            class attribute. Valid value are fetched from the MySQL database set with
            ``settings.CAS_SQL_*`` settings parameters using the query
            ``settings.CAS_SQL_USER_QUERY``.
    """

    def __init__(self, username):
        warnings.warn(
            (
                "MysqlAuthUser authentication class is deprecated: "
                "use cas_server.auth.SqlAuthUser instead"
            ),
            UserWarning
        )
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
            Tests ``password`` against the user-supplied password.

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


class SqlAuthUser(DBAuthUser):  # pragma: no cover
    """
        A SQL authentication class: authenticate user against a SQL database. The SQL database
        must be configures in settings.py as ``settings.DATABASES['cas_server']``.

        :param unicode username: A username, stored in the :attr:`username<AuthUser.username>`
            class attribute. Valid value are fetched from the MySQL database set with
            ``settings.CAS_SQL_*`` settings parameters using the query
            ``settings.CAS_SQL_USER_QUERY``.
    """

    def __init__(self, username):
        if "cas_server" not in connections:
            raise RuntimeError("Please configure the 'cas_server' database in settings.DATABASES")
        for retry_nb in range(3):
            try:
                with connections["cas_server"].cursor() as curs:
                    curs.execute(settings.CAS_SQL_USER_QUERY, (username,))
                    results = dictfetchall(curs)
                    if len(results) == 1:
                        self.user = results[0]
                        super(SqlAuthUser, self).__init__(self.user['username'])
                    else:
                        super(SqlAuthUser, self).__init__(username)
                break
            except DatabaseError:
                connections["cas_server"].close()
                if retry_nb == 2:
                    raise

    def test_password(self, password):
        """
            Tests ``password`` against the user-supplied password.

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
                settings.CAS_SQL_PASSWORD_CHARSET
            )
        else:
            return False


class LdapAuthUser(DBAuthUser):  # pragma: no cover
    """
        A ldap authentication class: authenticate user against a ldap database

        :param unicode username: A username, stored in the :attr:`username<AuthUser.username>`
            class attribute. Valid value are fetched from the ldap database set with
            ``settings.CAS_LDAP_*`` settings parameters.
    """

    _conn = None

    @classmethod
    def get_conn(cls):
        """Return a connection object to the ldap database"""
        conn = cls._conn
        if conn is None or conn.closed:
            conn = ldap3.Connection(
                settings.CAS_LDAP_SERVER,
                settings.CAS_LDAP_USER,
                settings.CAS_LDAP_PASSWORD,
                client_strategy="RESTARTABLE",
                auto_bind=True
            )
            cls._conn = conn
        return conn

    def __init__(self, username):
        if not ldap3:
            raise RuntimeError("Please install ldap3 before using the LdapAuthUser backend")
        if not settings.CAS_LDAP_BASE_DN:
            raise ValueError(
                "You must define CAS_LDAP_BASE_DN for using the ldap authentication backend"
            )
        # in case we got deconnected from the database, retry to connect 2 times
        for retry_nb in range(3):
            try:
                conn = self.get_conn()
                if conn.search(
                    settings.CAS_LDAP_BASE_DN,
                    settings.CAS_LDAP_USER_QUERY % ldap3.utils.conv.escape_bytes(username),
                    attributes=ldap3.ALL_ATTRIBUTES
                ) and len(conn.entries) == 1:
                    # try the new ldap3>=2 API
                    try:
                        user = conn.entries[0].entry_attributes_as_dict
                        # store the user dn
                        user["dn"] = conn.entries[0].entry_dn
                    # fallback to ldap3<2 API
                    except (
                        ldap3.core.exceptions.LDAPKeyError,  # ldap3<1 exception
                        ldap3.core.exceptions.LDAPAttributeError  # ldap3<2 exception
                    ):
                        user = conn.entries[0].entry_get_attributes_dict()
                        # store the user dn
                        user["dn"] = conn.entries[0].entry_get_dn()
                    if user.get(settings.CAS_LDAP_USERNAME_ATTR):
                        self.user = user
                        super(LdapAuthUser, self).__init__(user[settings.CAS_LDAP_USERNAME_ATTR][0])
                    else:
                        super(LdapAuthUser, self).__init__(username)
                else:
                    super(LdapAuthUser, self).__init__(username)
                break
            except ldap3.core.exceptions.LDAPCommunicationError:
                if retry_nb == 2:
                    raise

    def test_password(self, password):
        """
            Tests ``password`` against the user-supplied password.

            :param unicode password: a clear text password as submited by the user.
            :return: ``True`` if :attr:`username<AuthUser.username>` is valid and ``password`` is
                correct, ``False`` otherwise.
            :rtype: bool
        """
        if self.user and settings.CAS_LDAP_PASSWORD_CHECK == "bind":
            try:
                conn = ldap3.Connection(
                    settings.CAS_LDAP_SERVER,
                    self.user["dn"],
                    password,
                    auto_bind=True
                )
                try:
                    # fetch the user attribute
                    if conn.search(
                        settings.CAS_LDAP_BASE_DN,
                        settings.CAS_LDAP_USER_QUERY % ldap3.utils.conv.escape_bytes(self.username),
                        attributes=ldap3.ALL_ATTRIBUTES
                    ) and len(conn.entries) == 1:
                        # try the ldap3>=2 API
                        try:
                            attributes = conn.entries[0].entry_attributes_as_dict
                            # store the user dn
                            attributes["dn"] = conn.entries[0].entry_dn
                        # fallback to ldap<2 API
                        except (
                            ldap3.core.exceptions.LDAPKeyError,  # ldap3<1 exception
                            ldap3.core.exceptions.LDAPAttributeError  # ldap3<2 exception
                        ):
                            attributes = conn.entries[0].entry_get_attributes_dict()
                            attributes["dn"] = conn.entries[0].entry_get_dn()
                        # cache the attributes locally as we wont have access to the user password
                        # later.
                        user = UserAttributes.objects.get_or_create(username=self.username)[0]
                        user.attributs = attributes
                        user.save()
                finally:
                    conn.unbind()
                return True
            except (
                ldap3.core.exceptions.LDAPBindError,
                ldap3.core.exceptions.LDAPCommunicationError
            ):
                return False
        elif self.user and self.user.get(settings.CAS_LDAP_PASSWORD_ATTR):
            return check_password(
                settings.CAS_LDAP_PASSWORD_CHECK,
                password,
                self.user[settings.CAS_LDAP_PASSWORD_ATTR][0],
                settings.CAS_LDAP_PASSWORD_CHARSET
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
        if settings.CAS_LDAP_PASSWORD_CHECK == "bind":
            if settings.CAS_LDAP_ATTRS_VIEW == 1:
                user = UserAttributes.objects.get(username=self.username)
                return user.attributs
            else:
                return self.user
        else:
            return super(LdapAuthUser, self).attributs()


class DjangoAuthUser(AuthUser):  # pragma: no cover
    """
        A django auth class: authenticate user against django internal users

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
            Tests ``password`` against the user-supplied password.

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
            # _meta.get_fields() is from the new documented _meta interface in django 1.8
            try:
                field_names = [
                    field.attname for field in self.user._meta.get_fields()
                    if hasattr(field, "attname")
                ]
            # backward compatibility with django 1.7
            except AttributeError:  # pragma: no cover (only used by django 1.7)
                field_names = self.user._meta.get_all_field_names()
            for name in field_names:
                attr[name] = getattr(self.user, name)

            # unfold user_permissions many to many relation
            if 'user_permissions' in attr:
                attr['user_permissions'] = [
                    (
                        u"%s.%s" % (
                            perm.content_type.model_class().__module__,
                            perm.content_type.model_class().__name__
                        ),
                        perm.codename
                    ) for perm in attr['user_permissions'].filter()
                ]

            # unfold group many to many relation
            if 'groups' in attr:
                attr['groups'] = [group.name for group in attr['groups'].filter()]

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
            Tests ``password`` against the user-supplied password.

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
