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
"""template tags for the app"""
from django import template
from django import forms

register = template.Library()


@register.filter(name='is_checkbox')
def is_checkbox(field):
    """
        check if a form bound field is a checkbox

       :param django.forms.BoundField field: A bound field
       :return: ``True`` if the field is a checkbox, ``False`` otherwise.
       :rtype: bool
    """
    return isinstance(field.field.widget, forms.CheckboxInput)


@register.filter(name='is_hidden')
def is_hidden(field):
    """
        check if a form bound field is hidden

       :param django.forms.BoundField field: A bound field
       :return: ``True`` if the field is hidden, ``False`` otherwise.
       :rtype: bool
    """
    return isinstance(field.field.widget, forms.HiddenInput)
