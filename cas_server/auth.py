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
    """Authentication base class"""
    def __init__(self, username):
        self.username = username

    def test_password(self, password):
        """test `password` agains the user"""
        raise NotImplementedError()

    def attributs(self):
        """return a dict of user attributes"""
        raise NotImplementedError()


class DummyAuthUser(AuthUser):  # pragma: no cover
    """A Dummy authentication class"""

    def __init__(self, username):
        super(DummyAuthUser, self).__init__(username)

    def test_password(self, password):
        """test `password` agains the user"""
        return False

    def attributs(self):
        """return a dict of user attributes"""
        return {}


class TestAuthUser(AuthUser):
    """A test authentication class with one user test having
    alose test as password and some attributes"""

    def __init__(self, username):
        super(TestAuthUser, self).__init__(username)

    def test_password(self, password):
        """test `password` agains the user"""
        return self.username == settings.CAS_TEST_USER and password == settings.CAS_TEST_PASSWORD

    def attributs(self):
        """return a dict of user attributes"""
        return settings.CAS_TEST_ATTRIBUTES


class MysqlAuthUser(AuthUser):  # pragma: no cover
    """A mysql auth class: authentication user agains a mysql database"""
    user = None

    def __init__(self, username):
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
        """test `password` agains the user"""
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
        """return a dict of user attributes"""
        if self.user:
            return self.user
        else:
            return {}


class DjangoAuthUser(AuthUser):  # pragma: no cover
    """A django auth class: authenticate user agains django internal users"""
    user = None

    def __init__(self, username):
        User = get_user_model()
        try:
            self.user = User.objects.get(username=username)
        except User.DoesNotExist:
            pass
        super(DjangoAuthUser, self).__init__(username)

    def test_password(self, password):
        """test `password` agains the user"""
        if self.user:
            return self.user.check_password(password)
        else:
            return False

    def attributs(self):
        """return a dict of user attributes"""
        if self.user:
            attr = {}
            for field in self.user._meta.fields:
                attr[field.attname] = getattr(self.user, field.attname)
            return attr
        else:
            return {}


class CASFederateAuth(AuthUser):
    """Authentication class used then CAS_FEDERATE is True"""
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
        """test `password` agains the user"""
        if not self.user or not self.user.ticket:
            return False
        else:
            return (
                ticket == self.user.ticket and
                self.user.last_update >
                (timezone.now() - timedelta(seconds=settings.CAS_TICKET_VALIDITY))
            )

    def attributs(self):
        """return a dict of user attributes"""
        if not self.user:  # pragma: no cover (should not happen)
            return {}
        else:
            return self.user.attributs
