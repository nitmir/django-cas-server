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
"""urls for the app"""
from django.conf.urls import patterns, url
from django.views.generic import RedirectView

from . import views

urlpatterns = patterns(
    '',
    url(r'^$', RedirectView.as_view(pattern_name="login")),
    url('^login$', views.LoginView.as_view(), name='login'),
    url('^logout$', views.LogoutView.as_view(), name='logout'),
    url('^validate$', views.validate, name='validate'),
    url('^serviceValidate$', views.service_validate, name='serviceValidate'),
    url('^proxyValidate$', views.proxy_validate, name='proxyValidate'),
    url('^proxy$', views.proxy, name='proxy'),
    url('^p3/serviceValidate$', views.p3_service_validate, name='p3_serviceValidate'),
    url('^p3/proxyValidate$', views.p3_proxy_validate, name='p3_proxyValidate'),
    url('^samlValidate$', views.saml_validate, name='samlValidate'),
)

