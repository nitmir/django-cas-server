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
"""A django CAS server application"""
try:
    import django
except ModuleNotFoundError:
    django = None

#: version of the application
VERSION = '2.0.0'

if django is None or django.VERSION < (3, 2):
    #: path the the application configuration class
    default_app_config = 'cas_server.apps.CasAppConfig'
