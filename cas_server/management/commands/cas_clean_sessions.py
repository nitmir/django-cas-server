"""Clean deleted sessions management command"""
from django.core.management.base import BaseCommand
from django.utils.translation import ugettext_lazy as _

from ... import models


class Command(BaseCommand):
    """Clean deleted sessions"""
    args = ''
    help = _(u"Clean deleted sessions")

    def handle(self, *args, **options):
        models.User.clean_deleted_sessions()
