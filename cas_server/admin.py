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
from django.contrib import admin
from .models import ServiceTicket, ProxyTicket, ProxyGrantingTicket, User, ServicePattern
from .models import Username, ReplaceAttributName, ReplaceAttributValue, FilterAttributValue
from .models import FederatedIendityProvider
from .forms import TicketForm

TICKETS_READONLY_FIELDS = ('validate', 'service', 'service_pattern',
                           'creation', 'renew', 'single_log_out', 'value')
TICKETS_FIELDS = ('validate', 'service', 'service_pattern',
                  'creation', 'renew', 'single_log_out')


class ServiceTicketInline(admin.TabularInline):
    """`ServiceTicket` in admin interface"""
    model = ServiceTicket
    extra = 0
    form = TicketForm
    readonly_fields = TICKETS_READONLY_FIELDS
    fields = TICKETS_FIELDS


class ProxyTicketInline(admin.TabularInline):
    """`ProxyTicket` in admin interface"""
    model = ProxyTicket
    extra = 0
    form = TicketForm
    readonly_fields = TICKETS_READONLY_FIELDS
    fields = TICKETS_FIELDS


class ProxyGrantingInline(admin.TabularInline):
    """`ProxyGrantingTicket` in admin interface"""
    model = ProxyGrantingTicket
    extra = 0
    form = TicketForm
    readonly_fields = TICKETS_READONLY_FIELDS
    fields = TICKETS_FIELDS[1:]


class UserAdmin(admin.ModelAdmin):
    """`User` in admin interface"""
    inlines = (ServiceTicketInline, ProxyTicketInline, ProxyGrantingInline)
    readonly_fields = ('username', 'date', "session_key")
    fields = ('username', 'date', "session_key")
    list_display = ('username', 'date', "session_key")


class UsernamesInline(admin.TabularInline):
    """`Username` in admin interface"""
    model = Username
    extra = 0


class ReplaceAttributNameInline(admin.TabularInline):
    """`ReplaceAttributName` in admin interface"""
    model = ReplaceAttributName
    extra = 0


class ReplaceAttributValueInline(admin.TabularInline):
    """`ReplaceAttributValue` in admin interface"""
    model = ReplaceAttributValue
    extra = 0


class FilterAttributValueInline(admin.TabularInline):
    """`FilterAttributValue` in admin interface"""
    model = FilterAttributValue
    extra = 0


class ServicePatternAdmin(admin.ModelAdmin):
    """`ServicePattern` in admin interface"""
    inlines = (
        UsernamesInline,
        ReplaceAttributNameInline,
        ReplaceAttributValueInline,
        FilterAttributValueInline
    )
    list_display = ('pos', 'name', 'pattern', 'proxy',
                    'single_log_out', 'proxy_callback', 'restrict_users')


class FederatedIendityProviderAdmin(admin.ModelAdmin):
    """`FederatedIendityProvider` in admin interface"""
    fields = ('pos', 'suffix', 'server_url', 'cas_protocol_version', 'verbose_name', 'display')
    list_display = ('verbose_name', 'suffix', 'display')


admin.site.register(User, UserAdmin)
admin.site.register(ServicePattern, ServicePatternAdmin)
admin.site.register(FederatedIendityProvider, FederatedIendityProviderAdmin)
