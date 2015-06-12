from __future__ import absolute_import
from .init import *

from django.test import RequestFactory

import os
import pytest

from cas_server.views import Validate
from cas_server import models

from .dummy import *

@pytest.mark.django_db
def test_validate_view_ok():
    factory = RequestFactory()
    request = factory.get('/validate?ticket=ST-random&service=https://www.example.com')

    request.session = DummySession()

    models.ServiceTicket.objects = DummyTicketManager(models.ServiceTicket, 'https://www.example.com', "ST-random")

    validate = Validate()
    response = validate.get(request)

    assert response.status_code == 200
    assert response.content == "yes\n"



@pytest.mark.django_db
def test_validate_view_badservice():
    factory = RequestFactory()
    request = factory.get('/validate?ticket=ST-random&service=https://www.example2.com')

    request.session = DummySession()

    models.ServiceTicket.objects = DummyTicketManager(models.ServiceTicket, 'https://www.example.com', "ST-random")

    validate = Validate()
    response = validate.get(request)

    assert response.status_code == 200
    assert response.content == "no\n"



@pytest.mark.django_db
def test_validate_view_badticket():
    factory = RequestFactory()
    request = factory.get('/validate?ticket=ST-random2&service=https://www.example.com')

    request.session = DummySession()

    models.ServiceTicket.objects = DummyTicketManager(models.ServiceTicket, 'https://www.example.com', "ST-random1")

    validate = Validate()
    response = validate.get(request)

    assert response.status_code == 200
    assert response.content == "no\n"
