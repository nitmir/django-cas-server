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
# (c) 2016 Valentin Samir
"""Some test authentication classes for the CAS"""
from cas_server import auth


class TestCachedAttributesAuthUser(auth.TestAuthUser):
    """
        A test authentication class only working for one unique user.

        :param unicode username: A username, stored in the :attr:`username<AuthUser.username>`
            class attribute. The uniq valid value is ``settings.CAS_TEST_USER``.
    """
    def attributs(self):
        """
            The user attributes.

            :raises NotImplementedError: as this class do not support fetching user attributes
        """
        raise NotImplementedError()
