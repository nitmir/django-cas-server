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


class BootsrapForm(forms.Form):
    """Form base class to use boostrap then rendering the form fields"""
    def __init__(self, *args, **kwargs):
        super(BootsrapForm, self).__init__(*args, **kwargs)
        for (name, field) in self.fields.items():
            # Only tweak the fiel if it will be displayed
            if not isinstance(field.widget, forms.HiddenInput):
                # tell to display the field (used in form.html)
                self[name].display = True
                attrs = {}
                if isinstance(field.widget, forms.CheckboxInput):
                    self[name].checkbox = True
                else:
                    attrs['class'] = "form-control"
                    if field.label:
                        attrs["placeholder"] = field.label
                if field.required:
                    attrs["required"] = "required"
                field.widget.attrs.update(attrs)


class WarnForm(BootsrapForm):
    """
        Bases: :class:`django.forms.Form`

        Form used on warn page before emiting a ticket
    """

    #: The service url for which the user want a ticket
    service = forms.CharField(widget=forms.HiddenInput(), required=False)
    #: Is the service asking the authentication renewal ?
    renew = forms.BooleanField(widget=forms.HiddenInput(), required=False)
    #: Url to redirect to if the authentication fail (user not authenticated or bad service)
    gateway = forms.CharField(widget=forms.HiddenInput(), required=False)
    method = forms.CharField(widget=forms.HiddenInput(), required=False)
    #: ``True`` if the user has been warned of the ticket emission
    warned = forms.BooleanField(widget=forms.HiddenInput(), required=False)
    #: A valid LoginTicket to prevent POST replay
    lt = forms.CharField(widget=forms.HiddenInput(), required=False)


class FederateSelect(BootsrapForm):
    """
        Bases: :class:`django.forms.Form`

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
    #: The service url for which the user want a ticket
    service = forms.CharField(label=_('service'), widget=forms.HiddenInput(), required=False)
    method = forms.CharField(widget=forms.HiddenInput(), required=False)
    #: A checkbox to remember the user choices of :attr:`provider<FederateSelect.provider>`
    remember = forms.BooleanField(label=_('Remember the identity provider'), required=False)
    #: A checkbox to ask to be warn before emiting a ticket for another service
    warn = forms.BooleanField(label=_('warn'), required=False)
    #: Is the service asking the authentication renewal ?
    renew = forms.BooleanField(widget=forms.HiddenInput(), required=False)


class UserCredential(BootsrapForm):
    """
         Bases: :class:`django.forms.Form`

         Form used on the login page to retrive user credentials
     """
    #: The user username
    username = forms.CharField(label=_('login'))
    #: The service url for which the user want a ticket
    service = forms.CharField(label=_('service'), widget=forms.HiddenInput(), required=False)
    #: The user password
    password = forms.CharField(label=_('password'), widget=forms.PasswordInput)
    #: A valid LoginTicket to prevent POST replay
    lt = forms.CharField(widget=forms.HiddenInput(), required=False)
    method = forms.CharField(widget=forms.HiddenInput(), required=False)
    #: A checkbox to ask to be warn before emiting a ticket for another service
    warn = forms.BooleanField(label=_('warn'), required=False)
    #: Is the service asking the authentication renewal ?
    renew = forms.BooleanField(widget=forms.HiddenInput(), required=False)

    def __init__(self, *args, **kwargs):
        super(UserCredential, self).__init__(*args, **kwargs)

    def clean(self):
        """
            Validate that the submited :attr:`username` and :attr:`password` are valid

            :raises django.forms.ValidationError: if the :attr:`username` and :attr:`password`
                are not valid.
            :return: The cleaned POST data
            :rtype: dict
        """
        cleaned_data = super(UserCredential, self).clean()
        auth = utils.import_attr(settings.CAS_AUTH_CLASS)(cleaned_data.get("username"))
        if auth.test_password(cleaned_data.get("password")):
            cleaned_data["username"] = auth.username
        else:
            raise forms.ValidationError(_(u"Bad user"))
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
    #: the user username with the ``@`` component
    username = forms.CharField(widget=forms.HiddenInput())
    #: The service url for which the user want a ticket
    service = forms.CharField(widget=forms.HiddenInput(), required=False)
    #: The ``ticket`` used to authenticate the user against a provider
    password = forms.CharField(widget=forms.HiddenInput())
    #: alias of :attr:`password`
    ticket = forms.CharField(widget=forms.HiddenInput())
    #: A valid LoginTicket to prevent POST replay
    lt = forms.CharField(widget=forms.HiddenInput(), required=False)
    method = forms.CharField(widget=forms.HiddenInput(), required=False)
    #: Has the user asked to be warn before emiting a ticket for another service
    warn = forms.BooleanField(widget=forms.HiddenInput(), required=False)
    #: Is the service asking the authentication renewal ?
    renew = forms.BooleanField(widget=forms.HiddenInput(), required=False)

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
