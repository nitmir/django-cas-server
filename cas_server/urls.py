# ⁻*- coding: utf-8 -*-
from django.conf.urls import patterns, url
from django.views.generic import RedirectView

import views

urlpatterns = patterns('',
    url(r'^$', RedirectView.as_view(pattern_name="login")),
    url('^login$', views.login, name='login'),
    url('^logout$', views.logout, name='logout'),
    url('^validate$', views.validate, name='validate'),
    url('^serviceValidate$', views.serviceValidate, name='serviceValidate'),
    url('^proxyValidate$', views.proxyValidate, name='proxyValidate'),
    url('^proxy$', views.proxy, name='proxy'),
    url('^p3/serviceValidate$', views.p3_serviceValidate, name='p3_serviceValidate'),
    url('^p3/proxyValidate$', views.p3_proxyValidate, name='p3_proxyValidate'),
    url('^samlValidate$', views.samlValidate, name='samlValidate'),
)

