from __future__ import absolute_import
from .init import *

from django.test import RequestFactory

import os
import pytest
from lxml import etree
from cas_server.views import ValidateService
from cas_server import models

from .dummy import *

@pytest.mark.django_db
@dummy_ticket(models.ServiceTicket, 'https://www.example.com', "ST-random")
def test_validate_service_view_ok():
    factory = RequestFactory()
    request = factory.get('/serviceValidate?ticket=ST-random&service=https://www.example.com')

    request.session = DummySession()

    validate = ValidateService()
    validate.allow_proxy_ticket = False
    response = validate.get(request)

    assert response.status_code == 200

    root = etree.fromstring(response.content)
    users = root.xpath("//cas:user", namespaces={'cas': "http://www.yale.edu/tp/cas"})

    assert len(users) == 1
    assert users[0].text == "test"

    attributes = root.xpath("//cas:attributes", namespaces={'cas': "http://www.yale.edu/tp/cas"})

    assert len(attributes) == 1
    
    attrs = {}
    for attr in attributes[0]:
        attrs[attr.tag[len("http://www.yale.edu/tp/cas")+2:]]=attr.text

    assert 'mail' in attrs
    assert attrs['mail'] == 'test@example.com'



@pytest.mark.django_db
@dummy_ticket(models.ServiceTicket, 'https://www.example2.com', "ST-random")
def test_validate_service_view_badservice():
    factory = RequestFactory()
    request = factory.get('/serviceValidate?ticket=ST-random&service=https://www.example1.com')

    request.session = DummySession()

    validate = ValidateService()
    validate.allow_proxy_ticket = False
    response = validate.get(request)

    assert response.status_code == 200

    root = etree.fromstring(response.content)

    error = root.xpath("//cas:authenticationFailure", namespaces={'cas': "http://www.yale.edu/tp/cas"})
    
    assert len(error) == 1
    assert error[0].attrib['code'] == 'INVALID_SERVICE'

@pytest.mark.django_db
@dummy_ticket(models.ServiceTicket, 'https://www.example.com', "ST-random2")
def test_validate_service_view_badticket():
    factory = RequestFactory()
    request = factory.get('/serviceValidate?ticket=ST-random1&service=https://www.example.com')

    request.session = DummySession()

    validate = ValidateService()
    validate.allow_proxy_ticket = False
    response = validate.get(request)

    assert response.status_code == 200

    root = etree.fromstring(response.content)

    error = root.xpath("//cas:authenticationFailure", namespaces={'cas': "http://www.yale.edu/tp/cas"})
    
    assert len(error) == 1
    assert error[0].attrib['code'] == 'INVALID_TICKET'
