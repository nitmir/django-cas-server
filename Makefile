.PHONY: clean build install dist test_venv
VERSION=0.4

build:
	python setup.py build

install:
	python setup.py install

clean:
	find ./ -name '*.pyc' -delete
	find ./ -name __pycache__ -delete
	rm -rf build django_cas_server.egg-info dist

clean_all: clean
	rm -rf test_venv .tox

dist:
	python setup.py sdist

test_venv: dist
	mkdir -p test_venv
	virtualenv test_venv
	test_venv/bin/pip install -U django-cas-server ./dist/django-cas-server-${VERSION}.tar.gz

test_venv/cas:
	mkdir -p test_venv/cas
	test_venv/bin/django-admin startproject cas test_venv/cas
	sed -i "s/'django.contrib.staticfiles',/'django.contrib.staticfiles',\n    'bootstrap3',\n    'cas_server',/" test_venv/cas/cas/settings.py
	sed -i "s/'django.middleware.clickjacking.XFrameOptionsMiddleware',/'django.middleware.clickjacking.XFrameOptionsMiddleware',\n    'django.middleware.locale.LocaleMiddleware',/" test_venv/cas/cas/settings.py
	sed -i 's/from django.conf.urls import url/from django.conf.urls import url, include/' test_venv/cas/cas/urls.py
	sed -i "s@url(r'^admin/', admin.site.urls),@url(r'^admin/', admin.site.urls),\n    url(r'^', include('cas_server.urls', namespace='cas_server')),@" test_venv/cas/cas/urls.py
	test_venv/bin/python test_venv/cas/manage.py migrate
	test_venv/bin/python test_venv/cas/manage.py createsuperuser
		

run_test_server: test_venv test_venv/cas
	test_venv/bin/python test_venv/cas/manage.py runserver
