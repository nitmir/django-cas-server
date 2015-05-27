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
"""forms for the app"""
import cas_server.default_settings

from django import forms
from django.conf import settings
from django.utils.translation import ugettext_lazy as _

from . import models

class UserCredential(forms.Form):
    """Form used on the login page to retrive user credentials"""
    username = forms.CharField(label=_('login'))
    service = forms.CharField(widget=forms.HiddenInput(), required=False)
    password = forms.CharField(label=_('password'), widget=forms.PasswordInput)
    method = forms.CharField(widget=forms.HiddenInput(), required=False)
    warn = forms.BooleanField(label=_('warn'), required=False)

    def __init__(self, *args, **kwargs):
        super(UserCredential, self).__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super(UserCredential, self).clean()
        auth = settings.CAS_AUTH_CLASS(cleaned_data.get("username"))
        if auth.test_password(cleaned_data.get("password")):
            try:
                user = models.User.objects.get(username=auth.username)
                user.attributs = auth.attributs()
                user.save()
            except models.User.DoesNotExist:
                user = models.User.objects.create(
                    username=auth.username,
                    attributs=auth.attributs()
                )
                user.save()
        else:
            raise forms.ValidationError(_(u"Bad user"))


class TicketForm(forms.ModelForm):
    """Form for Tickets in the admin interface"""
    class Meta:
        model = models.Ticket
        exclude = []
    service = forms.CharField(widget=forms.TextInput)
