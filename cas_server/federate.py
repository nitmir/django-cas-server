# ⁻*- coding: utf-8 -*-
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License version 3 for
# more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (c) 2015 Valentin Samir
from .default_settings import settings

from .cas import CASClient
from .models import FederatedUser, FederateSLO, User

from importlib import import_module

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore


class CASFederateValidateUser(object):
    username = None
    attributs = {}
    client = None

    def __init__(self, provider, service_url):
        self.provider = provider

        if provider in settings.CAS_FEDERATE_PROVIDERS:
            (server_url, version) = settings.CAS_FEDERATE_PROVIDERS[provider][:2]
            self.client = CASClient(
                service_url=service_url,
                version=version,
                server_url=server_url,
                renew=False,
            )

    def get_login_url(self):
        return self.client.get_login_url() if self.client is not None else False

    def get_logout_url(self, redirect_url=None):
        return self.client.get_logout_url(redirect_url) if self.client is not None else False

    def verify_ticket(self, ticket):
        """test `password` agains the user"""
        if self.client is None:
            return False
        username, attributs = self.client.verify_ticket(ticket)[:2]
        if username is not None:
            if attributs is None:
                attributs = {}
            attributs["provider"] = self.provider
            self.username = username
            self.attributs = attributs
            try:
                user = FederatedUser.objects.get(
                    username=username,
                    provider=self.provider
                )
                user.attributs = attributs
                user.ticket = ticket
                user.save()
            except FederatedUser.DoesNotExist:
                user = FederatedUser.objects.create(
                    username=username,
                    provider=self.provider,
                    attributs=attributs,
                    ticket=ticket
                )
                user.save()
            return True
        else:
            return False

    @staticmethod
    def register_slo(username, session_key, ticket):
        FederateSLO.objects.create(
            username=username,
            session_key=session_key,
            ticket=ticket
        )

    def clean_sessions(self, logout_request):
        try:
            slos = self.client.get_saml_slos(logout_request)
        except NameError:
            slos = []
        for slo in slos:
            try:
                for federate_slo in FederateSLO.objects.filter(ticket=slo.text):
                    session = SessionStore(session_key=federate_slo.session_key)
                    session.flush()
                    try:
                        user = User.objects.get(
                            username=federate_slo.username,
                            session_key=federate_slo.session_key
                        )
                        user.logout()
                        user.delete()
                    except User.DoesNotExist:
                        pass
                    federate_slo.delete()
            except FederateSLO.DoesNotExist:
                pass