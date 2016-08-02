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
"""tests for the customs template tags"""
from django.test import TestCase

from cas_server import forms
from cas_server.templatetags import cas_server


class TemplateTagsTestCase(TestCase):
    """tests for the customs template tags"""

    def test_is_checkbox(self):
        """test for the template filter is_checkbox"""
        form = forms.UserCredential()
        self.assertFalse(cas_server.is_checkbox(form["username"]))
        self.assertTrue(cas_server.is_checkbox(form["warn"]))

    def test_is_hidden(self):
        """test for the template filter is_hidden"""
        form = forms.UserCredential()
        self.assertFalse(cas_server.is_hidden(form["username"]))
        self.assertTrue(cas_server.is_hidden(form["lt"]))
