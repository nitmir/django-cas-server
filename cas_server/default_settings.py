from django.conf import settings

def setting_default(name, default_value):
    value = getattr(settings, name, default_value)
    setattr(settings, name, value)

class AuthUser(object):
    def __init__(self, username):
        self.username = username

    def test_password(self, password):
        return self.username == "test" and password == "test"

    def attributs(self):
        return {'nom':'Nymous', 'prenom':'Ano', 'email':'anonymous@example.net'}


setting_default('CAS_LOGIN_TEMPLATE', 'cas_server/login.html')
setting_default('CAS_WARN_TEMPLATE', 'cas_server/warn.html')
setting_default('CAS_LOGGED_TEMPLATE', 'cas_server/logged.html')
setting_default('CAS_AUTH_CLASS', AuthUser)
setting_default('CAS_ST_LEN', 30)
setting_default('CAS_TICKET_VALIDITY', 300)
setting_default('CAS_PROXY_CA_CERTIFICATE_PATH', True)
