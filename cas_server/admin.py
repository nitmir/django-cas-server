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

class ServicePatternAdmin(admin.ModelAdmin):
    list_display = ('pos', 'pattern', 'proxy')


admin.site.register(User, UserAdmin)
admin.site.register(ServicePattern, ServicePatternAdmin)
#admin.site.register(ProxyGrantingTicketIOU, admin.ModelAdmin)
