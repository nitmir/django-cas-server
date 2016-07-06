import os
import pkg_resources
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))


# if we have Django 1.8 available, use last version of django-boostrap3
try:
    pkg_resources.require('Django >= 1.8')
    django_bootstrap3 = 'django-bootstrap3 >= 5.4'
    django = 'Django >= 1.8,<1.10'
except pkg_resources.VersionConflict:
    # Else if we have django 1.7, we need django-boostrap3 < 7.0.0
    try:
        pkg_resources.require('Django >= 1.7')
        django_bootstrap3 = 'django-bootstrap3 >= 5.4,<7.0.0'
        django = 'Django >= 1.7,<1.8'
    except (pkg_resources.VersionConflict, pkg_resources.DistributionNotFound):
        # Else we need to install Django, assume version will be >= 1.8
        django_bootstrap3 = 'django-bootstrap3 >= 5.4'
        django = 'Django >= 1.8,<1.10'
# No version of django installed, assume version will be >= 1.8
except pkg_resources.DistributionNotFound:
    django_bootstrap3 = 'django-bootstrap3 >= 5.4'
    django = 'Django >= 1.8,<1.10'

setup(
    name='django-cas-server',
    version='0.6.0',
    packages=[
        'cas_server', 'cas_server.migrations',
        'cas_server.management', 'cas_server.management.commands',
        'cas_server.tests'
    ],
    include_package_data=True,
    license='GPLv3',
    description=(
        'A Django Central Authentication Service server '
        'implementing the CAS Protocol 3.0 Specification'
    ),
    long_description=README,
    author='Valentin Samir',
    author_email='valentin.samir@crans.org',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
    package_data={
        'cas_server': [
            'templates/cas_server/*',
            'static/cas_server/*',
            'locale/*/LC_MESSAGES/*',
        ]
    },
    keywords=['django', 'cas', 'cas3', 'server', 'sso', 'single sign-on', 'authentication', 'auth'],
    install_requires=[
        django, 'requests >= 2.4', 'requests_futures >= 0.9.5',
        'django-picklefield >= 0.3.1', django_bootstrap3, 'lxml >= 3.4',
        'six >= 1'
    ],
    url="https://github.com/nitmir/django-cas-server",
    download_url="https://github.com/nitmir/django-cas-server/releases",
    zip_safe=False
)
