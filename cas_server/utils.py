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
"""Some util function for the app"""
from . import default_settings

from django.conf import settings

import urlparse
import urllib
import random
import string

def update_url(url, params):
    """update params in the `url` query string"""
    url_parts = list(urlparse.urlparse(url))
    query = dict(urlparse.parse_qsl(url_parts[4]))
    query.update(params)
    url_parts[4] = urllib.urlencode(query)
    return urlparse.urlunparse(url_parts)

def unpack_nested_exception(error):
    """If exception are stacked, return the first one"""
    i = 0
    while True:
        if error.args[i:]:
            if isinstance(error.args[i], Exception):
                error = error.args[i]
                i = 0
            else:
                i += 1
        else:
            break
    return error


def _gen_ticket(prefix):
    """Generate a ticket with prefix `prefix`"""
    return '%s-%s' % (
        prefix,
        ''.join(
            random.choice(
                string.ascii_letters + string.digits
            ) for _ in range(settings.CAS_ST_LEN)
        )
    )

def gen_st():
    """Generate a Service Ticket"""
    return _gen_ticket('ST')

def gen_pt():
    """Generate a Proxy Ticket"""
    return _gen_ticket('PT')

def gen_pgt():
    """Generate a Proxy Granting Ticket"""
    return _gen_ticket('PGT')

def gen_pgtiou():
    """Generate a Proxy Granting Ticket IOU"""
    return _gen_ticket('PGTIOU')


def gen_saml_id():
    return _gen_ticket('_')
