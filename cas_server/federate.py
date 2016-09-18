# -*- coding: utf-8 -*-
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License version 3 for
# more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (c) 2016 Valentin Samir
"""federated mode helper classes"""
from .default_settings import SessionStore
from django.db import IntegrityError

from .cas import CASClient
from .models import FederatedUser, FederateSLO, User

import logging
from six.moves import urllib

#: logger facility
logger = logging.getLogger(__name__)


class CASFederateValidateUser(object):
    """
        Class CAS client used to authenticate the user again a CAS provider

        :param cas_server.models.FederatedIendityProvider provider: The provider to use for
            authenticate the user.
        :param unicode service_url: The service url to transmit to the ``provider``.
    """
    #: the provider returned username
    username = None
    #: the provider returned attributes
    attributs = {}
    #: the CAS client instance
    client = None
    #: the provider returned username this the provider suffix appended
    federated_username = None
    #: the identity provider
    provider = None

    def __init__(self, provider, service_url, renew=False):
        self.provider = provider
        self.client = CASClient(
            service_url=service_url,
            version=provider.cas_protocol_version,
            server_url=provider.server_url,
            renew=renew,
        )

    def get_login_url(self):
        """
            :return: the CAS provider login url
            :rtype: unicode
        """
        return self.client.get_login_url()

    def get_logout_url(self, redirect_url=None):
        """
            :param redirect_url: The url to redirect to after logout from the provider, if provided.
            :type redirect_url: :obj:`unicode` or :obj:`NoneType<types.NoneType>`
            :return: the CAS provider logout url
            :rtype: unicode
        """
        return self.client.get_logout_url(redirect_url)

    def verify_ticket(self, ticket):
        """
            test ``ticket`` against the CAS provider, if valid, create a
            :class:`FederatedUser<cas_server.models.FederatedUser>` matching provider returned
            username and attributes.

            :param unicode ticket: The ticket to validate against the provider CAS
            :return: ``True`` if the validation succeed, else ``False``.
            :rtype: bool
        """
        try:
            username, attributs = self.client.verify_ticket(ticket)[:2]
        except urllib.error.URLError:
            return False
        if username is not None:
            if attributs is None:
                attributs = {}
            attributs["provider"] = self.provider.suffix
            self.username = username
            self.attributs = attributs
            user = FederatedUser.objects.update_or_create(
                username=username,
                provider=self.provider,
                defaults=dict(attributs=attributs, ticket=ticket)
            )[0]
            user.save()
            self.federated_username = user.federated_username
            return True
        else:
            return False

    @staticmethod
    def register_slo(username, session_key, ticket):
        """
            association a ``ticket`` with a (``username``, ``session_key``) for processing later SLO
            request by creating a :class:`cas_server.models.FederateSLO` object.

            :param unicode username: A logged user username, with the ``@`` component.
            :param unicode session_key: A logged user session_key matching ``username``.
            :param unicode ticket: A ticket used to authentication ``username`` for the session
                ``session_key``.
        """
        try:
            FederateSLO.objects.create(
                username=username,
                session_key=session_key,
                ticket=ticket
            )
        except IntegrityError:  # pragma: no cover (ignore if the FederateSLO already exists)
            pass

    def clean_sessions(self, logout_request):
        """
            process a SLO request: Search for ticket values in ``logout_request``. For each
            ticket value matching a :class:`cas_server.models.FederateSLO`, disconnect the
            corresponding user.

            :param unicode logout_request: An XML document contening one or more Single Log Out
                requests.
        """
        try:
            slos = self.client.get_saml_slos(logout_request) or []
        except NameError:  # pragma: no cover (should not happen)
            slos = []
        for slo in slos:
            for federate_slo in FederateSLO.objects.filter(ticket=slo.text):
                logger.info(
                    "Got an SLO requests for ticket %s, logging out user %s" % (
                        federate_slo.username,
                        federate_slo.ticket
                    )
                )
                session = SessionStore(session_key=federate_slo.session_key)
                session.flush()
                try:
                    user = User.objects.get(
                        username=federate_slo.username,
                        session_key=federate_slo.session_key
                    )
                    user.logout()
                    user.delete()
                except User.DoesNotExist:  # pragma: no cover (should not happen)
                    pass
                federate_slo.delete()
