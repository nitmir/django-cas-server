from __future__ import absolute_import
from .init import *

from django.test import RequestFactory

import os
import pytest

from cas_server.views import LogoutView
from cas_server import models

from .dummy import *


@pytest.mark.django_db
def test_logout_view():
    factory = RequestFactory()
    request = factory.get('/logout')

    request.session = DummySession()

    request.session["authenticated"] = True
    request.session["username"] = "test"
    request.session["warn"] = False

    models.User.objects = DummyUserManager(username="test", session_key=request.session.session_key)
    dlist = [None]
    models.User.delete = lambda x:dlist.pop()

    logout = LogoutView()
    response = logout.get(request)

    assert response.status_code == 200
    assert dlist == []
    assert not request.session.get("authenticated")
    assert not request.session.get("username")
    assert not request.session.get("warn")


@pytest.mark.django_db
def test_logout_view_url():
    factory = RequestFactory()
    request = factory.get('/logout?url=https://www.example.com')

    request.session = DummySession()

    request.session["authenticated"] = True
    request.session["username"] = "test"
    request.session["warn"] = False

    models.User.objects = DummyUserManager(username="test", session_key=request.session.session_key)
    dlist = [None]
    models.User.delete = lambda x:dlist.pop()

    logout = LogoutView()
    response = logout.get(request)

    assert response.status_code == 302
    assert response['Location'] == 'https://www.example.com'
    assert dlist == []
    assert not request.session.get("authenticated")
    assert not request.session.get("username")
    assert not request.session.get("warn")



@pytest.mark.django_db
def test_logout_view_service():
    factory = RequestFactory()
    request = factory.get('/logout?service=https://www.example.com')

    request.session = DummySession()

    request.session["authenticated"] = True
    request.session["username"] = "test"
    request.session["warn"] = False

    models.User.objects = DummyUserManager(username="test", session_key=request.session.session_key)
    dlist = [None]
    models.User.delete = lambda x:dlist.pop()

    logout = LogoutView()
    response = logout.get(request)

    assert response.status_code == 302
    assert response['Location'] == 'https://www.example.com'
    assert dlist == []
    assert not request.session.get("authenticated")
    assert not request.session.get("username")
    assert not request.session.get("warn")


