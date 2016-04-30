from __future__ import absolute_import
from .init import *

from django.test import RequestFactory

import os
import pytest

from cas_server.views import Validate
from cas_server import models

from .dummy import *

@pytest.mark.django_db
@dummy_ticket(models.ServiceTicket, 'https://www.example.com', "ST-random")
def test_validate_view_ok():
    factory = RequestFactory()
    request = factory.get('/validate?ticket=ST-random&service=https://www.example.com')

    request.session = DummySession()

    validate = Validate()
    response = validate.get(request)

    assert response.status_code == 200
    assert response.content == b"yes\ntest\n"



@pytest.mark.django_db
@dummy_ticket(models.ServiceTicket, 'https://www.example.com', "ST-random")
def test_validate_view_badservice():
    factory = RequestFactory()
    request = factory.get('/validate?ticket=ST-random&service=https://www.example2.com')

    request.session = DummySession()

    validate = Validate()
    response = validate.get(request)

    assert response.status_code == 200
    assert response.content == b"no\n"



@pytest.mark.django_db
@dummy_ticket(models.ServiceTicket, 'https://www.example.com', "ST-random1")
def test_validate_view_badticket():
    factory = RequestFactory()
    request = factory.get('/validate?ticket=ST-random2&service=https://www.example.com')

    request.session = DummySession()

    validate = Validate()
    response = validate.get(request)

    assert response.status_code == 200
    assert response.content == b"no\n"
