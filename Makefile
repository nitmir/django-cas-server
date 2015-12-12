.PHONY: clean build install dist
build:
	python setup.py build

install:
	python setup.py install

clean:
	find ./ -name '*.pyc' -delete
	find ./ -name __pycache__ -delete
	rm -rf build django_cas_server.egg-info dist

dist:
	python setup.py sdist
