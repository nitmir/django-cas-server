from django.core.management.base import BaseCommand
from django.utils.translation import ugettext_lazy as _

from ... import models


class Command(BaseCommand):
    args = ''
    help = _(u"Clean old trickets")

    def handle(self, *args, **options):
        models.User.clean_old_entries()
        for ticket_class in [models.ServiceTicket, models.ProxyTicket, models.ProxyGrantingTicket]:
            ticket_class.clean_old_entries()
