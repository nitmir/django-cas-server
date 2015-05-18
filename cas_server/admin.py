from django.contrib import admin
from models import *
from forms import *
# Register your models here.

class ServiceTicketInline(admin.TabularInline):
    model = ServiceTicket
    extra = 0
    form = TicketForm
class ProxyTicketInline(admin.TabularInline):
    model = ProxyTicket
    extra = 0
    form = TicketForm
class ProxyGrantingInline(admin.TabularInline):
    model = ProxyGrantingTicket
    extra = 0
    form = TicketForm

class UserAdmin(admin.ModelAdmin):
    inlines = (ServiceTicketInline, ProxyTicketInline, ProxyGrantingInline)

class UsernamesInline(admin.TabularInline):
    model = Usernames
    extra = 0
class ReplaceAttributNameInline(admin.TabularInline):
    model = ReplaceAttributName
    extra = 0
class ReplaceAttributValueInline(admin.TabularInline):
    model = ReplaceAttributValue
    extra = 0
class FilterAttributValueInline(admin.TabularInline):
    model = FilterAttributValue
    extra = 0

class ServicePatternAdmin(admin.ModelAdmin):
    inlines = (UsernamesInline, ReplaceAttributNameInline, ReplaceAttributValueInline, FilterAttributValueInline)
    list_display = ('pos', 'name', 'pattern', 'proxy')


admin.site.register(User, UserAdmin)
admin.site.register(ServicePattern, ServicePatternAdmin)
#admin.site.register(ProxyGrantingTicketIOU, admin.ModelAdmin)
