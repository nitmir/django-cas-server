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
# (c) 2015-2016 Valentin Samir
"""urls for the app"""
from django.conf.urls import url
from django.views.generic import RedirectView
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables

from cas_server import views

app_name = "cas_server"

urlpatterns = [
    url(r'^$', RedirectView.as_view(pattern_name="cas_server:login", permanent=False)),
    url(
        '^login$',
        sensitive_post_parameters('password')(
            views.LoginView.as_view()
        ),
        name='login'
    ),
    url('^logout$', views.LogoutView.as_view(), name='logout'),
    url('^validate$', views.Validate.as_view(), name='validate'),
    url(
        '^serviceValidate$',
        views.ValidateService.as_view(allow_proxy_ticket=False),
        name='serviceValidate'
    ),
    url(
        '^proxyValidate$',
        views.ValidateService.as_view(allow_proxy_ticket=True),
        name='proxyValidate'
    ),
    url('^proxy$', views.Proxy.as_view(), name='proxy'),
    url(
        '^p3/serviceValidate$',
        views.ValidateService.as_view(allow_proxy_ticket=False),
        name='p3_serviceValidate'
    ),
    url(
        '^p3/proxyValidate$',
        views.ValidateService.as_view(allow_proxy_ticket=True),
        name='p3_proxyValidate'
    ),
    url('^samlValidate$', views.SamlValidate.as_view(), name='samlValidate'),
    url(
        '^auth$',
        sensitive_variables('password', 'secret')(
            sensitive_post_parameters('password', 'secret')(
                views.Auth.as_view()
            )
        ),
        name='auth'
    ),
    url("^federate(?:/(?P<provider>([^/]+)))?$", views.FederateAuth.as_view(), name='federateAuth'),
]
