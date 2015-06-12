from __future__ import absolute_import
from .init import *

from django.test import RequestFactory

import os
import pytest

from cas_server.views import LoginView
from cas_server import models

from .dummy import *



def test_login_view_post_goodpass_goodlt():
    factory = RequestFactory()
    request = factory.post('/login', {'username':'test', 'password':'test', 'lt':'LT-random'})
    request.session = DummySession()

    request.session['lt'] = 'LT-random'

    request.session["username"] = os.urandom(20)
    request.session["warn"] = os.urandom(20)

    login = LoginView()
    login.init_post(request)

    ret = login.process_post(pytest=True)

    assert ret == LoginView.USER_LOGIN_OK
    assert request.session.get("authenticated") == True
    assert request.session.get("username") == "test"
    assert request.session.get("warn") == False

def test_login_view_post_badlt():
    factory = RequestFactory()
    request = factory.post('/login', {'username':'test', 'password':'test', 'lt':'LT-random1'})
    request.session = DummySession()

    request.session['lt'] = 'LT-random2'

    authenticated = os.urandom(20)
    username = os.urandom(20)
    warn = os.urandom(20)

    request.session["authenticated"] = authenticated
    request.session["username"] = username
    request.session["warn"] = warn

    login = LoginView()
    login.init_post(request)

    ret = login.process_post(pytest=True)

    assert ret == LoginView.INVALID_LOGIN_TICKET
    assert request.session.get("authenticated") == authenticated
    assert request.session.get("username") == username
    assert request.session.get("warn") == warn

def test_login_view_post_badpass_good_lt():
    factory = RequestFactory()
    request = factory.post('/login', {'username':'test', 'password':'badpassword', 'lt':'LT-random'})
    request.session = DummySession()

    request.session['lt'] = 'LT-random'

    login = LoginView()
    login.init_post(request)
    ret = login.process_post()

    assert ret == LoginView.USER_LOGIN_FAILURE
    assert not request.session.get("authenticated")
    assert not request.session.get("username")
    assert not request.session.get("warn")


def test_view_login_get_unauth():
    factory = RequestFactory()
    request = factory.post('/login')
    request.session = DummySession()

    login = LoginView()
    login.init_get(request)
    ret = login.process_get()

    assert ret == LoginView.USER_NOT_AUTHENTICATED

    login = LoginView()
    response = login.get(request)

    assert response.status_code == 200

@pytest.mark.django_db
def test_view_login_get_auth():
    factory = RequestFactory()
    request = factory.post('/login')
    request.session = DummySession()

    request.session["authenticated"] = True
    request.session["username"] = "test"
    request.session["warn"] = False

    login = LoginView()
    login.init_get(request)
    ret = login.process_get()

    assert ret == LoginView.USER_AUTHENTICATED

    models.User.objects = DummyUserManager(username="test", session_key=request.session.session_key)

    login = LoginView()
    response = login.get(request)

    assert response.status_code == 200

@pytest.mark.django_db
def test_view_login_get_auth_service():
    factory = RequestFactory()
    request = factory.post('/login?service=https://www.example.com')
    request.session = DummySession()

    request.session["authenticated"] = True
    request.session["username"] = "test"
    request.session["warn"] = False

    login = LoginView()
    login.init_get(request)
    ret = login.process_get()

    assert ret == LoginView.USER_AUTHENTICATED

    models.User.objects = DummyUserManager(username="test", session_key=request.session.session_key)
    models.User.save = lambda x:None
    models.ServiceTicket.objects = DummyTicketManager(models.ServiceTicket, 'https://www.example.com', "ST-random")
    models.ServicePattern.validate = classmethod(lambda x,y: models.ServicePattern())
    models.ServiceTicket.save = lambda x:None

    login = LoginView()
    response = login.get(request)

    assert response.status_code == 302
    assert response['Location'].startswith('https://www.example.com?ticket=ST-')

@pytest.mark.django_db
def test_view_login_get_auth_service_warn():
    factory = RequestFactory()
    request = factory.post('/login?service=https://www.example.com')
    request.session = DummySession()

    request.session["authenticated"] = True
    request.session["username"] = "test"
    request.session["warn"] = True

    login = LoginView()
    login.init_get(request)
    ret = login.process_get()

    assert ret == LoginView.USER_AUTHENTICATED

    models.User.objects = DummyUserManager(username="test", session_key=request.session.session_key)
    models.User.save = lambda x:None
    models.ServiceTicket.objects = DummyTicketManager(models.ServiceTicket, 'https://www.example.com', "ST-random")
    models.ServicePattern.validate = classmethod(lambda x,y: models.ServicePattern())
    models.ServiceTicket.save = lambda x:None

    login = LoginView()
    response = login.get(request)

    assert response.status_code == 200
