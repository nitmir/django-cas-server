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
"""Default values for the app's settings"""
from django.conf import settings


def setting_default(name, default_value):
    """if the config `name` is not set, set it the `default_value`"""
    value = getattr(settings, name, default_value)
    setattr(settings, name, value)

setting_default('CAS_LOGIN_TEMPLATE', 'cas_server/login.html')
setting_default('CAS_WARN_TEMPLATE', 'cas_server/warn.html')
setting_default('CAS_LOGGED_TEMPLATE', 'cas_server/logged.html')
setting_default('CAS_LOGOUT_TEMPLATE', 'cas_server/logout.html')
setting_default('CAS_AUTH_CLASS', 'cas_server.auth.DjangoAuthUser')
# All CAS implementation MUST support ST and PT up to 32 chars,
# PGT and PGTIOU up to 64 chars and it is RECOMMENDED that all
# tickets up to 256 chars are supports so we use 64 for the default
# len.
setting_default('CAS_TICKET_LEN', 64)

setting_default('CAS_LT_LEN', settings.CAS_TICKET_LEN)
setting_default('CAS_ST_LEN', settings.CAS_TICKET_LEN)
setting_default('CAS_PT_LEN', settings.CAS_TICKET_LEN)
setting_default('CAS_PGT_LEN', settings.CAS_TICKET_LEN)
setting_default('CAS_PGTIOU_LEN', settings.CAS_TICKET_LEN)

setting_default('CAS_TICKET_VALIDITY', 60)
setting_default('CAS_PGT_VALIDITY', 3600)
setting_default('CAS_TICKET_TIMEOUT', 24*3600)
setting_default('CAS_PROXY_CA_CERTIFICATE_PATH', True)
setting_default('CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT', False)

setting_default('CAS_AUTH_SHARED_SECRET', '')

setting_default('CAS_LOGIN_TICKET_PREFIX', 'LT')
# Service tickets MUST begin with the characters ST so you should not change this
# Services MUST be able to accept service tickets of up to 32 characters in length
setting_default('CAS_SERVICE_TICKET_PREFIX', 'ST')
# Proxy tickets SHOULD begin with the characters, PT.
# Back-end services MUST be able to accept proxy tickets of up to 32 characters.
setting_default('CAS_PROXY_TICKET_PREFIX', 'PT')
# Proxy-granting tickets SHOULD begin with the characters PGT
# Services MUST be able to handle proxy-granting tickets of up to 64
setting_default('CAS_PROXY_GRANTING_TICKET_PREFIX', 'PGT')
# Proxy-granting ticket IOUs SHOULD begin with the characters, PGTIOU
# Services MUST be able to handle PGTIOUs of up to 64 characters in length.
setting_default('CAS_PROXY_GRANTING_TICKET_IOU_PREFIX', 'PGTIOU')

# Maximum number of parallel single log out requests send
# if more requests need to be send, there are queued
setting_default('CAS_SLO_MAX_PARALLEL_REQUESTS', 10)

setting_default('CAS_SQL_HOST', 'localhost')
setting_default('CAS_SQL_USERNAME', '')
setting_default('CAS_SQL_PASSWORD', '')
setting_default('CAS_SQL_DBNAME', '')
setting_default('CAS_SQL_DBCHARSET', 'utf8')
setting_default('CAS_SQL_USER_QUERY', 'SELECT user AS usersame, pass AS '
                'password, users.* FROM users WHERE user = %s')
setting_default('CAS_SQL_PASSWORD_CHECK', 'crypt')  # crypt or plain
