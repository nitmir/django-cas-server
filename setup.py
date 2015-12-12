import os
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-cas-server',
    version='0.3.5',
    packages=[
        'cas_server', 'cas_server.migrations',
        'cas_server.management', 'cas_server.management.commands'
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
        'Django >= 1.7,<1.10', 'requests >= 2.4', 'requests_futures >= 0.9.5',
        'django-picklefield >= 0.3.1', 'django-bootstrap3 >= 5.4', 'lxml >= 3.4'
    ],
    url="https://github.com/nitmir/django-cas-server",
    download_url="https://github.com/nitmir/django-cas-server/releases",
    zip_safe=False
)
