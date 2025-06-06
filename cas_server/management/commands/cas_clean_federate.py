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
# (c) 2016-2020 Valentin Samir
from django.core.management.base import BaseCommand

from ... import models

import sys
if sys.version_info < (3, ):
    from django.utils.translation import ugettext_lazy as _
else:
    from django.utils.translation import gettext_lazy as _


class Command(BaseCommand):
    args = ''
    help = _(u"Clean old federated users")

    def handle(self, *args, **options):
        models.FederatedUser.clean_old_entries()
        models.FederateSLO.clean_deleted_sessions()
