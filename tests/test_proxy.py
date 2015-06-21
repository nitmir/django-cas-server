from __future__ import absolute_import
from tests.init import *

from django.test import RequestFactory

import os
import pytest
from lxml import etree
from cas_server.views import ValidateService, Proxy
from cas_server import models

from tests.dummy import *

@pytest.mark.django_db
@dummy_ticket(models.ProxyGrantingTicket, '', "PGT-random")
@dummy_service_pattern(proxy=True)
@dummy_user(username="test", session_key="test_session")
@dummy_ticket(models.ProxyTicket, "https://www.example.com", "PT-random")
@dummy_proxy
def test_proxy_ok():
    factory = RequestFactory()
    request = factory.get('/proxy?pgt=PGT-random&targetService=https://www.example.com')

    request.session = DummySession()

    proxy = Proxy()
    response = proxy.get(request)

    assert response.status_code == 200

    root = etree.fromstring(response.content)
    proxy_tickets = root.xpath("//cas:proxyTicket", namespaces={'cas': "http://www.yale.edu/tp/cas"})

    assert len(proxy_tickets) == 1

    factory = RequestFactory()
    request = factory.get('/proxyValidate?ticket=PT-random&service=https://www.example.com')

    validate = ValidateService()
    validate.allow_proxy_ticket = True
    response = validate.get(request)
    
    assert response.status_code == 200

    root = etree.fromstring(response.content)
    users = root.xpath("//cas:user", namespaces={'cas': "http://www.yale.edu/tp/cas"})

    assert len(users) == 1
    assert users[0].text == "test"



