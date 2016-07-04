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
"""forms for the app"""
from .default_settings import settings

from django import forms
from django.utils.translation import ugettext_lazy as _

import cas_server.utils as utils
import cas_server.models as models


class WarnForm(forms.Form):
    """Form used on warn page before emiting a ticket"""
    service = forms.CharField(widget=forms.HiddenInput(), required=False)
    renew = forms.BooleanField(widget=forms.HiddenInput(), required=False)
    gateway = forms.CharField(widget=forms.HiddenInput(), required=False)
    method = forms.CharField(widget=forms.HiddenInput(), required=False)
    warned = forms.BooleanField(widget=forms.HiddenInput(), required=False)
    lt = forms.CharField(widget=forms.HiddenInput(), required=False)


class FederateSelect(forms.Form):
    """
        Form used on the login page when CAS_FEDERATE is True
        allowing the user to choose a identity provider.
    """
    provider = forms.ModelChoiceField(
        queryset=models.FederatedIendityProvider.objects.filter(display=True).order_by(
            "pos",
            "verbose_name",
            "suffix"
        ),
        to_field_name="suffix",
        label=_('Identity provider'),
    )
    service = forms.CharField(label=_('service'), widget=forms.HiddenInput(), required=False)
    method = forms.CharField(widget=forms.HiddenInput(), required=False)
    remember = forms.BooleanField(label=_('Remember the identity provider'), required=False)
    warn = forms.BooleanField(label=_('warn'), required=False)
    renew = forms.BooleanField(widget=forms.HiddenInput(), required=False)


class UserCredential(forms.Form):
    """Form used on the login page to retrive user credentials"""
    username = forms.CharField(label=_('login'))
    service = forms.CharField(label=_('service'), widget=forms.HiddenInput(), required=False)
    password = forms.CharField(label=_('password'), widget=forms.PasswordInput)
    lt = forms.CharField(widget=forms.HiddenInput(), required=False)
    method = forms.CharField(widget=forms.HiddenInput(), required=False)
    warn = forms.BooleanField(label=_('warn'), required=False)
    renew = forms.BooleanField(widget=forms.HiddenInput(), required=False)

    def __init__(self, *args, **kwargs):
        super(UserCredential, self).__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super(UserCredential, self).clean()
        auth = utils.import_attr(settings.CAS_AUTH_CLASS)(cleaned_data.get("username"))
        if auth.test_password(cleaned_data.get("password")):
            cleaned_data["username"] = auth.username
        else:
            raise forms.ValidationError(_(u"Bad user"))
        return cleaned_data


class FederateUserCredential(UserCredential):
    """Form used on the login page to retrive user credentials"""
    username = forms.CharField(widget=forms.HiddenInput())
    service = forms.CharField(widget=forms.HiddenInput(), required=False)
    password = forms.CharField(widget=forms.HiddenInput())
    ticket = forms.CharField(widget=forms.HiddenInput())
    lt = forms.CharField(widget=forms.HiddenInput(), required=False)
    method = forms.CharField(widget=forms.HiddenInput(), required=False)
    warn = forms.BooleanField(widget=forms.HiddenInput(), required=False)
    renew = forms.BooleanField(widget=forms.HiddenInput(), required=False)

    def clean(self):
        cleaned_data = super(FederateUserCredential, self).clean()
        try:
            user = models.FederatedUser.get_from_federated_username(cleaned_data["username"])
            user.ticket = ""
            user.save()
        # should not happed as if the FederatedUser do not exists, super should
        # raise before a ValidationError("bad user")
        except models.FederatedUser.DoesNotExist:  # pragma: no cover (should not happend)
            raise forms.ValidationError(
                _(u"User not found in the temporary database, please try to reconnect")
            )
        return cleaned_data


class TicketForm(forms.ModelForm):
    """Form for Tickets in the admin interface"""
    class Meta:
        model = models.Ticket
        exclude = []
    service = forms.CharField(label=_('service'), widget=forms.TextInput)
