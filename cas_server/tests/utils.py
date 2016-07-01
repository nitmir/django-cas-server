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
# (c) 2016 Valentin Samir
"""Some utils functions for tests"""
from cas_server.default_settings import settings

from django.test import Client

import cgi
from threading import Thread
from lxml import etree
from six.moves import BaseHTTPServer
from six.moves.urllib.parse import urlparse, parse_qsl

from cas_server import models


def copy_form(form):
    """Copy form value into a dict"""
    params = {}
    for field in form:
        if field.value():
            params[field.name] = field.value()
        else:
            params[field.name] = ""
    return params


def get_login_page_params(client=None):
    """Return a client and the POST params for the client to login"""
    if client is None:
        client = Client()
    response = client.get('/login')
    params = copy_form(response.context["form"])
    return client, params


def get_auth_client(**update):
    """return a authenticated client"""
    client, params = get_login_page_params()
    params["username"] = settings.CAS_TEST_USER
    params["password"] = settings.CAS_TEST_PASSWORD
    params.update(update)

    client.post('/login', params)
    assert client.session.get("authenticated")

    return client


def get_user_ticket_request(service):
    """Make an auth client to request a ticket for `service`, return the tuple (user, ticket)"""
    client = get_auth_client()
    response = client.get("/login", {"service": service})
    ticket_value = response['Location'].split('ticket=')[-1]
    user = models.User.objects.get(
        username=settings.CAS_TEST_USER,
        session_key=client.session.session_key
    )
    ticket = models.ServiceTicket.objects.get(value=ticket_value)
    return (user, ticket, client)


def get_validated_ticket(service):
    """Return a tick that has being already validated. Used to test SLO"""
    (ticket, auth_client) = get_user_ticket_request(service)[1:3]

    client = Client()
    response = client.get('/validate', {'ticket': ticket.value, 'service': service})
    assert (response.status_code == 200)
    assert (response.content == b'yes\ntest\n')

    ticket = models.ServiceTicket.objects.get(value=ticket.value)
    return (auth_client, ticket)


def get_pgt():
    """return a dict contening a service, user and PGT ticket for this service"""
    (httpd, host, port) = HttpParamsHandler.run()[0:3]
    service = "http://%s:%s" % (host, port)

    (user, ticket) = get_user_ticket_request(service)[:2]

    client = Client()
    client.get('/serviceValidate', {'ticket': ticket.value, 'service': service, 'pgtUrl': service})
    params = httpd.PARAMS

    params["service"] = service
    params["user"] = user

    return params


def get_proxy_ticket(service):
    """Return a ProxyTicket waiting for validation"""
    params = get_pgt()

    # get a proxy ticket
    client = Client()
    response = client.get('/proxy', {'pgt': params['pgtId'], 'targetService': service})
    root = etree.fromstring(response.content)
    proxy_ticket = root.xpath(
        "//cas:proxyTicket",
        namespaces={'cas': "http://www.yale.edu/tp/cas"}
    )
    proxy_ticket = proxy_ticket[0].text
    ticket = models.ProxyTicket.objects.get(value=proxy_ticket)
    return ticket


class HttpParamsHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """
        A simple http server that return 200 on GET or POST
        and store GET or POST parameters. Used in unit tests
    """

    def do_GET(self):
        """Called on a GET request on the BaseHTTPServer"""
        self.send_response(200)
        self.send_header(b"Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")
        url = urlparse(self.path)
        params = dict(parse_qsl(url.query))
        self.server.PARAMS = params

    def do_POST(self):
        """Called on a POST request on the BaseHTTPServer"""
        ctype, pdict = cgi.parse_header(self.headers.get('content-type'))
        if ctype == 'multipart/form-data':
            postvars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers.get('content-length'))
            postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)
        else:
            postvars = {}
        self.server.PARAMS = postvars

    def log_message(self, *args):
        """silent any log message"""
        return

    @classmethod
    def run(cls):
        """Run a BaseHTTPServer using this class as handler"""
        server_class = BaseHTTPServer.HTTPServer
        httpd = server_class(("127.0.0.1", 0), cls)
        (host, port) = httpd.socket.getsockname()

        def lauch():
            """routine to lauch in a background thread"""
            httpd.handle_request()
            httpd.server_close()

        httpd_thread = Thread(target=lauch)
        httpd_thread.daemon = True
        httpd_thread.start()
        return (httpd, host, port)


class Http404Handler(HttpParamsHandler):
    """A simple http server that always return 404 not found. Used in unit tests"""
    def do_GET(self):
        """Called on a GET request on the BaseHTTPServer"""
        self.send_response(404)
        self.send_header(b"Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"error 404 not found")

    def do_POST(self):
        """Called on a POST request on the BaseHTTPServer"""
        return self.do_GET()
