from django.core.management.base import BaseCommand, CommandError
from django.utils.translation import ugettext_lazy as _

from ... import models

class Command(BaseCommand):
    args = ''
    help = _(u"Clean old trickets")

    def handle(self, *args, **options):
        for ticket_class in [models.ServiceTicket, models.ProxyTicket, models.ProxyGrantingTicket]:
            ticket_class.clean()
