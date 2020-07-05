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
"""django config module"""
from django.apps import AppConfig

import sys
if sys.version_info < (3, ):
    from django.utils.translation import ugettext_lazy as _
else:
    from django.utils.translation import gettext_lazy as _


class CasAppConfig(AppConfig):
    """
        Bases: :class:`django.apps.AppConfig`

        django CAS application config class
    """
    #: Full Python path to the application. It must be unique across a Django project.
    name = 'cas_server'
    #: Human-readable name for the application.
    verbose_name = _('Central Authentication Service')
