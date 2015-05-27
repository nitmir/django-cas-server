"""module for the admin interface of the app"""
from django.contrib import admin
from .models import ServiceTicket, ProxyTicket, ProxyGrantingTicket, User, ServicePattern
from .models import Username, ReplaceAttributName, ReplaceAttributValue, FilterAttributValue
from .forms import TicketForm
# Register your models here.

class ServiceTicketInline(admin.TabularInline):
    """`ServiceTicket` in admin interface"""
    model = ServiceTicket
    extra = 0
    form = TicketForm
class ProxyTicketInline(admin.TabularInline):
    """`ProxyTicket` in admin interface"""
    model = ProxyTicket
    extra = 0
    form = TicketForm
class ProxyGrantingInline(admin.TabularInline):
    """`ProxyGrantingTicket` in admin interface"""
    model = ProxyGrantingTicket
    extra = 0
    form = TicketForm

class UserAdmin(admin.ModelAdmin):
    """`User` in admin interface"""
    inlines = (ServiceTicketInline, ProxyTicketInline, ProxyGrantingInline)

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
    list_display = ('pos', 'name', 'pattern', 'proxy')


admin.site.register(User, UserAdmin)
admin.site.register(ServicePattern, ServicePatternAdmin)
