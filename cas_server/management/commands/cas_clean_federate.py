from django.core.management.base import BaseCommand
from django.utils.translation import ugettext_lazy as _

from ... import models


class Command(BaseCommand):
    args = ''
    help = _(u"Clean old federated users")

    def handle(self, *args, **options):
        models.FederatedUser.clean_old_entries()
        models.FederateSLO.clean_deleted_sessions()
