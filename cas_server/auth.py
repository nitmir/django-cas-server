# ⁻*- coding: utf-8 -*-
from django.conf import settings
from django.contrib.auth.models import User
try:
    import MySQLdb
    import MySQLdb.cursors
    import crypt
except ImportError:
    MySQLdb = None
class DummyAuthUser(object):
    def __init__(self, username):
        self.username = username

    def test_password(self, password):
        return False

    def attributs(self):
        return {}


class TestAuthUser(DummyAuthUser):
    def __init__(self, username):
        self.username = username

    def test_password(self, password):
        return self.username == "test" and password == "test"

    def attributs(self):
        return {'nom':'Nymous', 'prenom':'Ano', 'email':'anonymous@example.net'}


class MysqlAuthUser(DummyAuthUser):
    user = None
    def __init__(self, username):
        mysql_config = {
          "user": settings.CAS_SQL_USERNAME,
          "passwd": settings.CAS_SQL_PASSWORD,
          "db": settings.CAS_SQL_DBNAME,
          "host": settings.CAS_SQL_HOST,
          "charset":settings.CAS_SQL_DBCHARSET,
          "cursorclass":MySQLdb.cursors.DictCursor
        }
        if not MySQLdb:
            raise RuntimeError("Please install MySQLdb before using the MysqlAuthUser backend")
        conn = MySQLdb.connect(**mysql_config)
        curs = conn.cursor()
        if curs.execute(settings.CAS_SQL_USER_QUERY, (username,)) == 1:
            self.user = curs.fetchone()
        super(MysqlAuthUser, self).__init__(username)

    def test_password(self, password):
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
                    return crypt.crypt(password, self.user["password"][:2]) == self.user["password"]

    def attributs(self):
        if not self.user:
            return {}
        else:
            return self.user

        
class DjangoAuthUser(DummyAuthUser):
    user = None
    def __init__(self, username):
        try:
            self.user = User.objects.get(username=username)
        except User.DoesNotExist:
            pass
        super(DjangoAuthUser, self).__init__(username)


    def test_password(self, password):
        if not self.user:
            return False
        else:
            return self.user.check_password(password)

    def attributs(self):
        if not self.user:
            return {}
        else:
            attr = {}
            for field in self.user._meta.fields:
                attr[field.attname]=getattr(self.user, field.attname)
            return attr
