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
# (c) 2015 Valentin Samir
"""Some authentication classes for the CAS"""
from django.conf import settings
from django.contrib.auth import get_user_model
try:
    import MySQLdb
    import MySQLdb.cursors
    import crypt
except ImportError:
    MySQLdb = None


class AuthUser(object):
    def __init__(self, username):
        self.username = username

    def test_password(self, password):
        """test `password` agains the user"""
        raise NotImplemented()

    def attributs(self):
        """return a dict of user attributes"""
        raise NotImplemented()


class DummyAuthUser(AuthUser):
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
        return self.username == "test" and password == "test"

    def attributs(self):
        """return a dict of user attributes"""
        return {'nom': 'Nymous', 'prenom': 'Ano', 'email': 'anonymous@example.net'}


class MysqlAuthUser(AuthUser):
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

    def test_password(self, password):
        """test `password` agains the user"""
        if not self.user:
            return False
        else:
            if settings.CAS_SQL_PASSWORD_CHECK == "plain":
                return password == self.user["password"]
            elif settings.CAS_SQL_PASSWORD_CHECK == "crypt":
                if self.user["password"].startswith('$'):
                    salt = '$'.join(self.user["password"].split('$', 3)[:-1])
                    return crypt.crypt(password, salt) == self.user["password"]
                else:
                    return crypt.crypt(
                        password,
                        self.user["password"][:2]
                    ) == self.user["password"]

    def attributs(self):
        """return a dict of user attributes"""
        if not self.user:
            return {}
        else:
            return self.user


class DjangoAuthUser(AuthUser):
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
        if not self.user:
            return False
        else:
            return self.user.check_password(password)

    def attributs(self):
        """return a dict of user attributes"""
        if not self.user:
            return {}
        else:
            attr = {}
            for field in self.user._meta.fields:
                attr[field.attname] = getattr(self.user, field.attname)
            return attr
