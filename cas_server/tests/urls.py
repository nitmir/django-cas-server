"""cas URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""

try:
    from django.urls import re_path
except ImportError:
    # re_path is not available in Django 2
    from django.conf.urls import url as re_path

from django.conf.urls import include
from django.contrib import admin

urlpatterns = [
    re_path(r'^admin/', admin.site.urls),
    re_path(r'^', include('cas_server.urls', namespace='cas_server')),
]
