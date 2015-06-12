import django
from django.conf import settings
from django.contrib import messages

settings.configure()
settings.STATIC_URL = "/static/"
settings.DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': '/dev/null',
    }
}
settings.INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'bootstrap3',
    'cas_server',
)

settings.ROOT_URLCONF = "/"
settings.CAS_AUTH_CLASS = 'cas_server.auth.TestAuthUser'

try:
    django.setup()
except AttributeError:
    pass
messages.add_message = lambda x,y,z:None

