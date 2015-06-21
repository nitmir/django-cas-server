from __future__ import absolute_import
from .init import *

from django.test import RequestFactory

import os
import pytest

from cas_server.views import Auth
from cas_server import models

from .dummy import *

settings.CAS_AUTH_SHARED_SECRET = "test"

@pytest.mark.django_db
@dummy_ticket(models.ServiceTicket, 'https://www.example.com', "ST-random")
@dummy_user(username="test", session_key="test_session")
@dummy_service_pattern()
def test_auth_view_goodpass():
    factory = RequestFactory()
    request = factory.post('/auth', {'username':'test', 'password':'test', 'service':'https://www.example.com', 'secret':'test'})

    request.session = DummySession()

    auth = Auth()
    response = auth.post(request)

    assert response.status_code == 200
    assert response.content == b"yes\n"

@dummy_service_pattern()
@dummy_ticket(models.ServiceTicket, 'https://www.example.com', "ST-random")
@dummy_user(username="test", session_key="test_session")
def test_auth_view_badpass():
    factory = RequestFactory()
    request = factory.post('/auth', {'username':'test', 'password':'badpass', 'service':'https://www.example.com', 'secret':'test'})

    request.session = DummySession()

    auth = Auth()
    response = auth.post(request)

    assert response.status_code == 200
    assert response.content == b"no\n"

