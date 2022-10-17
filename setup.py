import os
import pkg_resources
from setuptools import setup
from cas_server import VERSION

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

if __name__ == '__main__':
    # allow setup.py to be run from any path
    os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

    setup(
        name='django-cas-server',
        version=VERSION,
        packages=[
            'cas_server', 'cas_server.migrations',
            'cas_server.management', 'cas_server.management.commands',
            'cas_server.tests', 'cas_server.templatetags'
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
            'Development Status :: 5 - Production/Stable',
            'Framework :: Django',
            'Framework :: Django :: 1.11',
            'Framework :: Django :: 2.2',
            'Framework :: Django :: 3.1',
            'Framework :: Django :: 3.2',
            'Intended Audience :: Developers',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
            'Operating System :: OS Independent',
            'Programming Language :: Python',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
            'Programming Language :: Python :: 3.7',
            'Programming Language :: Python :: 3.8',
            'Programming Language :: Python :: 3.9',
            'Programming Language :: Python :: 3.10',
            'Topic :: Software Development :: Libraries :: Python Modules',
            'Topic :: Internet :: WWW/HTTP',
            'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
            'Topic :: System :: Systems Administration :: Authentication/Directory'
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
            'Django >= 1.11,<4.2', 'requests >= 2.4', 'requests_futures >= 0.9.5',
            'lxml >= 3.4', 'six >= 1'
        ],
        url="https://github.com/nitmir/django-cas-server",
        download_url="https://github.com/nitmir/django-cas-server/releases/latest",
        zip_safe=False,
        setup_requires=['pytest-runner'],
        tests_require=['pytest', 'pytest-django', 'pytest-pythonpath', 'pytest-warnings', 'mock>=1'],
    )
