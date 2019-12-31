# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License version 3 for
# more details.
#
# You should have received a copy of the GNU General Public License version 3
# along with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (c) 2019 Alexandre Iooss
"""
Router for the example project

It also routes Django Admin, AdminDocs and Auth
"""

from django.conf.urls import include, url
from django.contrib import admin
from django.views.generic import RedirectView

urlpatterns = [
    # No app, so redirect to admin
    url(r'^$',
        RedirectView.as_view(pattern_name='cas_server:login'),
        name='index'),
    url(r'^cas/', include('cas_server.urls', namespace="cas_server")),

    # Include Django Contrib and Core routers
    url(r'^i18n/', include('django.conf.urls.i18n')),
    url(r'^accounts/login/',
        RedirectView.as_view(pattern_name='index'),
        name='login'),
    url(r'^accounts/', include('django.contrib.auth.urls')),
    url(r'^accounts/profile/', RedirectView.as_view(pattern_name='index')),
    url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
    url(r'^admin/', admin.site.urls),
]
