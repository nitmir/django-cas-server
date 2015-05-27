# ⁻*- coding: utf-8 -*-
"""urls for the app"""
from django.conf.urls import patterns, url
from django.views.generic import RedirectView

from . import views

urlpatterns = patterns(
    '',
    url(r'^$', RedirectView.as_view(pattern_name="login")),
    url('^login$', views.login, name='login'),
    url('^logout$', views.logout, name='logout'),
    url('^validate$', views.validate, name='validate'),
    url('^serviceValidate$', views.service_validate, name='serviceValidate'),
    url('^proxyValidate$', views.proxy_validate, name='proxyValidate'),
    url('^proxy$', views.proxy, name='proxy'),
    url('^p3/serviceValidate$', views.p3_service_validate, name='p3_serviceValidate'),
    url('^p3/proxyValidate$', views.p3_proxy_validate, name='p3_proxyValidate'),
    url('^samlValidate$', views.saml_validate, name='samlValidate'),
)

