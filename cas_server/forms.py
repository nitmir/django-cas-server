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
from django.forms import widgets

import cas_server.utils as utils
import cas_server.models as models

import sys
if sys.version_info < (3, ):
    from django.utils.translation import ugettext_lazy as _
else:
    from django.utils.translation import gettext_lazy as _


class BootsrapForm(forms.Form):
    """
        Bases: :class:`django.forms.Form`

        Form base class to use boostrap then rendering the form fields
    """
    def __init__(self, *args, **kwargs):
        super(BootsrapForm, self).__init__(*args, **kwargs)
        for field in self.fields.values():
            # Only tweak the field if it will be displayed
            if not isinstance(field.widget, widgets.HiddenInput):
                attrs = {}
                if (
                    isinstance(field.widget, (widgets.Input, widgets.Select, widgets.Textarea)) and
                    not isinstance(field.widget, (widgets.CheckboxInput,))
                ):
                    attrs['class'] = "form-control"
                if isinstance(field.widget, (widgets.Input, widgets.Textarea)) and field.label:
                    attrs["placeholder"] = field.label
                if field.required:
                    attrs["required"] = "required"
                field.widget.attrs.update(attrs)


class BaseLogin(BootsrapForm):
    """
        Bases: :class:`BootsrapForm`

        Base form with all field possibly hidden on the login pages
    """
    #: The service url for which the user want a ticket
    service = forms.CharField(widget=forms.HiddenInput(), required=False)
    #: A valid LoginTicket to prevent POST replay
    lt = forms.CharField(widget=forms.HiddenInput(), required=False)
    #: Is the service asking the authentication renewal ?
    renew = forms.BooleanField(widget=forms.HiddenInput(), required=False)
    #: Url to redirect to if the authentication fail (user not authenticated or bad service)
    gateway = forms.CharField(widget=forms.HiddenInput(), required=False)
    method = forms.CharField(widget=forms.HiddenInput(), required=False)


class WarnForm(BaseLogin):
    """
        Bases: :class:`BaseLogin`

        Form used on warn page before emiting a ticket
    """
    #: ``True`` if the user has been warned of the ticket emission
    warned = forms.BooleanField(widget=forms.HiddenInput(), required=False)


class FederateSelect(BaseLogin):
    """
        Bases: :class:`BaseLogin`

        Form used on the login page when ``settings.CAS_FEDERATE`` is ``True``
        allowing the user to choose an identity provider.
    """
    #: The providers the user can choose to be used as authentication backend
    provider = forms.ModelChoiceField(
        queryset=models.FederatedIendityProvider.objects.filter(display=True).order_by(
            "pos",
            "verbose_name",
            "suffix"
        ),
        to_field_name="suffix",
        label=_('Identity provider'),
    )
    #: A checkbox to ask to be warn before emiting a ticket for another service
    warn = forms.BooleanField(
        label=_('Warn me before logging me into other sites.'),
        required=False
    )
    #: A checkbox to remember the user choices of :attr:`provider<FederateSelect.provider>`
    remember = forms.BooleanField(label=_('Remember the identity provider'), required=False)


class UserCredential(BaseLogin):
    """
         Bases: :class:`BaseLogin`

         Form used on the login page to retrive user credentials
     """
    #: The user username
    username = forms.CharField(
        label=_('username'),
        widget=forms.TextInput(attrs={'autofocus': 'autofocus'})
    )
    #: The user password
    password = forms.CharField(label=_('password'), widget=forms.PasswordInput)
    #: A checkbox to ask to be warn before emiting a ticket for another service
    warn = forms.BooleanField(
        label=_('Warn me before logging me into other sites.'),
        required=False
    )

    def clean(self):
        """
            Validate that the submited :attr:`username` and :attr:`password` are valid

            :raises django.forms.ValidationError: if the :attr:`username` and :attr:`password`
                are not valid.
            :return: The cleaned POST data
            :rtype: dict
        """
        cleaned_data = super(UserCredential, self).clean()
        if "username" in cleaned_data and "password" in cleaned_data:
            auth = utils.import_attr(settings.CAS_AUTH_CLASS)(cleaned_data["username"])
            if auth.test_password(cleaned_data["password"]):
                cleaned_data["username"] = auth.username
            else:
                raise forms.ValidationError(
                    _(u"The credentials you provided cannot be determined to be authentic.")
                )
        return cleaned_data


class FederateUserCredential(UserCredential):
    """
        Bases: :class:`UserCredential`

        Form used on a auto submited page for linking the views
        :class:`FederateAuth<cas_server.views.FederateAuth>` and
        :class:`LoginView<cas_server.views.LoginView>`.

        On successful authentication on a provider, in the view
        :class:`FederateAuth<cas_server.views.FederateAuth>` a
        :class:`FederatedUser<cas_server.models.FederatedUser>` is created by
        :meth:`cas_server.federate.CASFederateValidateUser.verify_ticket` and the user is redirected
        to :class:`LoginView<cas_server.views.LoginView>`. This form is then automatically filled
        with infos matching the created :class:`FederatedUser<cas_server.models.FederatedUser>`
        using the ``ticket`` as one time password and submited using javascript. If javascript is
        not enabled, a connect button is displayed.

        This stub authentication form, allow to implement the federated mode with very few
        modificatons to the :class:`LoginView<cas_server.views.LoginView>` view.
    """

    def __init__(self, *args, **kwargs):
        super(FederateUserCredential, self).__init__(*args, **kwargs)
        # All fields are hidden and auto filled by the /login view logic
        for name, field in self.fields.items():
            field.widget = forms.HiddenInput()
            self[name].display = False

    def clean(self):
        """
            Validate that the submited :attr:`username` and :attr:`password` are valid using
            the :class:`CASFederateAuth<cas_server.auth.CASFederateAuth>` auth class.

            :raises django.forms.ValidationError: if the :attr:`username` and :attr:`password`
                do not correspond to a :class:`FederatedUser<cas_server.models.FederatedUser>`.
            :return: The cleaned POST data
            :rtype: dict
        """
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
    """
        Bases: :class:`django.forms.ModelForm`

        Form for Tickets in the admin interface
    """
    class Meta:
        model = models.Ticket
        exclude = []
    service = forms.CharField(label=_('service'), widget=forms.TextInput)
