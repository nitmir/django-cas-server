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

try:
    from django.urls import re_path
except ImportError:
    # re_path is not available in Django 2
    from django.conf.urls import url as re_path

from django.views.generic import RedirectView
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables

from cas_server import views

app_name = "cas_server"

urlpatterns = [
    re_path(
        r'^$',
        RedirectView.as_view(pattern_name="cas_server:login", permanent=False, query_string=True)
    ),
    re_path(
        '^login$',
        sensitive_post_parameters('password')(
            views.LoginView.as_view()
        ),
        name='login'
    ),
    re_path('^logout$', views.LogoutView.as_view(), name='logout'),
    re_path('^validate$', views.Validate.as_view(), name='validate'),
    re_path(
        '^serviceValidate$',
        views.ValidateService.as_view(allow_proxy_ticket=False),
        name='serviceValidate'
    ),
    re_path(
        '^proxyValidate$',
        views.ValidateService.as_view(allow_proxy_ticket=True),
        name='proxyValidate'
    ),
    re_path('^proxy$', views.Proxy.as_view(), name='proxy'),
    re_path(
        '^p3/serviceValidate$',
        views.ValidateService.as_view(allow_proxy_ticket=False),
        name='p3_serviceValidate'
    ),
    re_path(
        '^p3/proxyValidate$',
        views.ValidateService.as_view(allow_proxy_ticket=True),
        name='p3_proxyValidate'
    ),
    re_path('^samlValidate$', views.SamlValidate.as_view(), name='samlValidate'),
    re_path(
        '^auth$',
        sensitive_variables('password', 'secret')(
            sensitive_post_parameters('password', 'secret')(
                views.Auth.as_view()
            )
        ),
        name='auth'
    ),
    re_path("^federate(?:/(?P<provider>([^/]+)))?$",
            views.FederateAuth.as_view(), name='federateAuth'),
]
