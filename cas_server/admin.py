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
"""module for the admin interface of the app"""
from .default_settings import settings

from django.contrib import admin
from .models import ServiceTicket, ProxyTicket, ProxyGrantingTicket, User, ServicePattern
from .models import Username, ReplaceAttributName, ReplaceAttributValue, FilterAttributValue
from .models import FederatedIendityProvider, FederatedUser, UserAttributes
from .forms import TicketForm


class BaseInlines(admin.TabularInline):
    """
        Bases: :class:`django.contrib.admin.TabularInline`

        Base class for inlines in the admin interface.
    """
    #: This controls the number of extra forms the formset will display in addition to
    #: the initial forms.
    extra = 0


class UserAdminInlines(BaseInlines):
    """
        Bases: :class:`BaseInlines`

        Base class for inlines in :class:`UserAdmin` interface
    """
    #: The form :class:`TicketForm<cas_server.forms.TicketForm>` used to display tickets.
    form = TicketForm
    #: Fields to display on a object that are read only (not editable).
    readonly_fields = (
        'validate', 'service', 'service_pattern',
        'creation', 'renew', 'single_log_out', 'value'
    )
    #: Fields to display on a object.
    fields = (
        'validate', 'service', 'service_pattern',
        'creation', 'renew', 'single_log_out'
    )


class ServiceTicketInline(UserAdminInlines):
    """
        Bases: :class:`UserAdminInlines`

        :class:`ServiceTicket<cas_server.models.ServiceTicket>` in admin interface
    """
    #: The model which the inline is using.
    model = ServiceTicket


class ProxyTicketInline(UserAdminInlines):
    """
        Bases: :class:`UserAdminInlines`

        :class:`ProxyTicket<cas_server.models.ProxyTicket>` in admin interface
    """
    #: The model which the inline is using.
    model = ProxyTicket


class ProxyGrantingInline(UserAdminInlines):
    """
        Bases: :class:`UserAdminInlines`

        :class:`ProxyGrantingTicket<cas_server.models.ProxyGrantingTicket>` in admin interface
    """
    #: The model which the inline is using.
    model = ProxyGrantingTicket


class UserAdmin(admin.ModelAdmin):
    """
        Bases: :class:`django.contrib.admin.ModelAdmin`

        :class:`User<cas_server.models.User>` in admin interface
    """
    #: See :class:`ServiceTicketInline`, :class:`ProxyTicketInline`, :class:`ProxyGrantingInline`
    #: objects below the :class:`UserAdmin` fields.
    inlines = (ServiceTicketInline, ProxyTicketInline, ProxyGrantingInline)
    #: Fields to display on a object that are read only (not editable).
    readonly_fields = ('username', 'date', "session_key")
    #: Fields to display on a object.
    fields = ('username', 'date', "session_key")
    #: Fields to display on the list of class:`UserAdmin` objects.
    list_display = ('username', 'date', "session_key")


class UsernamesInline(BaseInlines):
    """
        Bases: :class:`BaseInlines`

        :class:`Username<cas_server.models.Username>` in admin interface
    """
    #: The model which the inline is using.
    model = Username


class ReplaceAttributNameInline(BaseInlines):
    """
        Bases: :class:`BaseInlines`

        :class:`ReplaceAttributName<cas_server.models.ReplaceAttributName>` in admin interface
    """
    #: The model which the inline is using.
    model = ReplaceAttributName


class ReplaceAttributValueInline(BaseInlines):
    """
        Bases: :class:`BaseInlines`

        :class:`ReplaceAttributValue<cas_server.models.ReplaceAttributValue>` in admin interface
    """
    #: The model which the inline is using.
    model = ReplaceAttributValue


class FilterAttributValueInline(BaseInlines):
    """
        Bases: :class:`BaseInlines`

        :class:`FilterAttributValue<cas_server.models.FilterAttributValue>` in admin interface
    """
    #: The model which the inline is using.
    model = FilterAttributValue


class ServicePatternAdmin(admin.ModelAdmin):
    """
        Bases: :class:`django.contrib.admin.ModelAdmin`

        :class:`ServicePattern<cas_server.models.ServicePattern>` in admin interface
    """
    #: See :class:`UsernamesInline`, :class:`ReplaceAttributNameInline`,
    #: :class:`ReplaceAttributValueInline`, :class:`FilterAttributValueInline` objects below
    #: the :class:`ServicePatternAdmin` fields.
    inlines = (
        UsernamesInline,
        ReplaceAttributNameInline,
        ReplaceAttributValueInline,
        FilterAttributValueInline
    )
    #: Fields to display on the list of class:`ServicePatternAdmin` objects.
    list_display = ('pos', 'name', 'pattern', 'proxy',
                    'single_log_out', 'proxy_callback', 'restrict_users')


class FederatedIendityProviderAdmin(admin.ModelAdmin):
    """
        Bases: :class:`django.contrib.admin.ModelAdmin`

        :class:`FederatedIendityProvider<cas_server.models.FederatedIendityProvider>` in admin
        interface
    """
    #: Fields to display on a object.
    fields = ('pos', 'suffix', 'server_url', 'cas_protocol_version', 'verbose_name', 'display')
    #: Fields to display on the list of class:`FederatedIendityProviderAdmin` objects.
    list_display = ('verbose_name', 'suffix', 'display')


class FederatedUserAdmin(admin.ModelAdmin):
    """
        Bases: :class:`django.contrib.admin.ModelAdmin`

        :class:`FederatedUser<cas_server.models.FederatedUser>` in admin
        interface
    """
    #: Fields to display on a object.
    fields = ('username', 'provider', 'last_update')
    #: Fields to display on the list of class:`FederatedUserAdmin` objects.
    list_display = ('username', 'provider', 'last_update')


class UserAttributesAdmin(admin.ModelAdmin):
    """
        Bases: :class:`django.contrib.admin.ModelAdmin`

        :class:`UserAttributes<cas_server.models.UserAttributes>` in admin
        interface
    """
    #: Fields to display on a object.
    fields = ('username', '_attributs')


admin.site.register(ServicePattern, ServicePatternAdmin)
admin.site.register(FederatedIendityProvider, FederatedIendityProviderAdmin)
if settings.DEBUG:  # pragma: no branch (we always test with DEBUG True)
    admin.site.register(User, UserAdmin)
    admin.site.register(FederatedUser, FederatedUserAdmin)
    admin.site.register(UserAttributes, UserAttributesAdmin)
