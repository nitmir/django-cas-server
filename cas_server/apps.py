"""django config module"""
from django.utils.translation import ugettext_lazy as _
from django.apps import AppConfig


class CasAppConfig(AppConfig):
    """django CAS application config class"""
    name = 'cas_server'
    verbose_name = _('Central Authentication Service')
