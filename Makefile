.PHONY: build dist
VERSION=`python setup.py -V`

build:
	python setup.py build

install: dist
	pip -V
	pip install --no-deps --upgrade --force-reinstall --find-links ./dist/django-cas-server-${VERSION}.tar.gz django-cas-server

uninstall:
	pip uninstall django-cas-server || true

clean_pyc:
	find ./ -name '*.pyc' -delete
	find ./ -name __pycache__ -delete
clean_build:
	rm -rf build django_cas_server.egg-info dist
clean_tox:
	rm -rf .tox
clean_test_venv:
	rm -rf test_venv

clean: clean_pyc clean_build

clean_all: clean_pyc clean_build clean_tox clean_test_venv

dist:
	python setup.py sdist

test_venv/bin/python:
	virtualenv test_venv
	test_venv/bin/pip install -U --requirement requirements-dev.txt Django

test_venv/cas/manage.py: test_venv
	mkdir -p test_venv/cas
	test_venv/bin/django-admin startproject cas test_venv/cas
	ln -s ../../cas_server test_venv/cas/cas_server
	sed -i "s/'django.contrib.staticfiles',/'django.contrib.staticfiles',\n    'bootstrap3',\n    'cas_server',/" test_venv/cas/cas/settings.py
	sed -i "s/'django.middleware.clickjacking.XFrameOptionsMiddleware',/'django.middleware.clickjacking.XFrameOptionsMiddleware',\n    'django.middleware.locale.LocaleMiddleware',/" test_venv/cas/cas/settings.py
	sed -i 's/from django.conf.urls import url/from django.conf.urls import url, include/' test_venv/cas/cas/urls.py
	sed -i "s@url(r'^admin/', admin.site.urls),@url(r'^admin/', admin.site.urls),\n    url(r'^', include('cas_server.urls', namespace='cas_server')),@" test_venv/cas/cas/urls.py
	test_venv/bin/python test_venv/cas/manage.py migrate
	test_venv/bin/python test_venv/cas/manage.py createsuperuser

test_venv/bin/coverage: test_venv
	test_venv/bin/pip install coverage

test_venv: test_venv/bin/python

test_project: test_venv/cas/manage.py
	@echo "##############################################################"
	@echo "A test django project was created in $(realpath test_venv/cas)"

run_test_server: test_project
	test_venv/bin/python test_venv/cas/manage.py runserver

tests: test_venv
	test_venv/bin/py.test

coverage: test_venv/bin/coverage
	test_venv/bin/coverage run test_venv/bin/py.test
	test_venv/bin/coverage html
	rm htmlcov/coverage_html.js  # I am really pissed off by those keybord shortcuts

coverage_codacy: coverage
	test_venv/bin/coverage xml
	test_venv/bin/pip install codacy-coverage
	test_venv/bin/python-codacy-coverage -r coverage.xml
