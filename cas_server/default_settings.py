from django.conf import settings
import auth

def setting_default(name, default_value):
    value = getattr(settings, name, default_value)
    setattr(settings, name, value)

setting_default('CAS_LOGIN_TEMPLATE', 'cas_server/login.html')
setting_default('CAS_WARN_TEMPLATE', 'cas_server/warn.html')
setting_default('CAS_LOGGED_TEMPLATE', 'cas_server/logged.html')
setting_default('CAS_AUTH_CLASS', auth.DjangoAuthUser)
setting_default('CAS_ST_LEN', 30)
setting_default('CAS_TICKET_VALIDITY', 300)
setting_default('CAS_PROXY_CA_CERTIFICATE_PATH', True)

setting_default('CAS_SQL_HOST', 'localhost')
setting_default('CAS_SQL_USERNAME', '')
setting_default('CAS_SQL_PASSWORD', '')
setting_default('CAS_SQL_DBNAME', '')
setting_default('CAS_SQL_DBCHARSET', 'utf8')
setting_default('CAS_SQL_USER_QUERY', 'SELECT user AS usersame, pass AS password, users.* FROM users WHERE user = %s')
setting_default('CAS_SQL_PASSWORD_CHECK', 'crypt') # crypt or plain

