"""Some utils functions for tests"""
from cas_server.default_settings import settings

from django.test import Client

from lxml import etree

from cas_server import models
from cas_server import utils


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
    (ticket, auth_client) = get_user_ticket_request(service)[1:3]

    client = Client()
    response = client.get('/validate', {'ticket': ticket.value, 'service': service})
    assert (response.status_code == 200)
    assert (response.content == b'yes\ntest\n')

    ticket = models.ServiceTicket.objects.get(value=ticket.value)
    return (auth_client, ticket)


def get_pgt():
    """return a dict contening a service, user and PGT ticket for this service"""
    (httpd, host, port) = utils.HttpParamsHandler.run()[0:3]
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
