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
setting_default('CAS_ST_LEN', 30)
setting_default('CAS_TICKET_VALIDITY', 300)
setting_default('CAS_TICKET_TIMEOUT', 24*3600)
setting_default('CAS_PROXY_CA_CERTIFICATE_PATH', True)
setting_default('CAS_REDIRECT_TO_LOGIN_AFTER_LOGOUT', False)

setting_default('CAS_AUTH_SHARED_SECRET', '')

setting_default('CAS_SERVICE_TICKET_PREFIX', 'ST')
setting_default('CAS_PROXY_TICKET_PREFIX', 'PT')
setting_default('CAS_PROXY_GRANTING_TICKET_PREFIX', 'PGT')
setting_default('CAS_PROXY_GRANTING_TICKET_IOU_PREFIX', 'PGTIOU')

setting_default('CAS_SQL_HOST', 'localhost')
setting_default('CAS_SQL_USERNAME', '')
setting_default('CAS_SQL_PASSWORD', '')
setting_default('CAS_SQL_DBNAME', '')
setting_default('CAS_SQL_DBCHARSET', 'utf8')
setting_default('CAS_SQL_USER_QUERY', 'SELECT user AS usersame, pass AS ' \
    'password, users.* FROM users WHERE user = %s')
setting_default('CAS_SQL_PASSWORD_CHECK', 'crypt') # crypt or plain

