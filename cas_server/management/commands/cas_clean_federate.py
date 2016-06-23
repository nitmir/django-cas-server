from django.core.management.base import BaseCommand
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone

from datetime import timedelta

from ... import models
from ...default_settings import settings


class Command(BaseCommand):
    args = ''
    help = _(u"Clean old federated users")

    def handle(self, *args, **options):
        federated_users = models.FederatedUser.objects.filter(
            last_update__lt=(timezone.now() - timedelta(seconds=settings.CAS_TICKET_TIMEOUT))
        )
        known_users = {user.username for user in models.User.objects.all()}
        for user in federated_users:
            if not ('%s@%s' % (user.username, user.provider)) in known_users:
                user.delete()
        models.FederateSLO.clean_deleted_sessions()