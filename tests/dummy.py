import functools
from cas_server import models

class DummyUserManager(object):
    def __init__(self, username, session_key):
        self.username = username
        self.session_key = session_key
    def get(self, username=None, session_key=None):
        if username == self.username and session_key == self.session_key:
            return models.User(username=username, session_key=session_key)
        else:
            raise models.User.DoesNotExist()


def dummy(*args, **kwds):
    pass

def dummy_service_pattern(**kwargs):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwds):
            service_validate = models.ServicePattern.validate
            models.ServicePattern.validate = classmethod(lambda x,y: models.ServicePattern(**kwargs))
            ret = func(*args, **kwds)
            models.ServicePattern.validate = service_validate
            return ret
        return wrapper
    return decorator

def dummy_user(username, session_key):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwds):
            user_manager = models.User.objects
            user_save = models.User.save
            user_delete = models.User.delete
            models.User.objects = DummyUserManager(username, session_key)
            models.User.save = dummy
            models.User.delete = dummy
            ret = func(*args, **kwds)
            models.User.objects = user_manager
            models.User.save = user_save
            models.User.delete = user_delete
            return ret
        return wrapper
    return decorator

def dummy_ticket(ticket_class, service, ticket):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwds):
            ticket_manager = ticket_class.objects
            ticket_save = ticket_class.save
            ticket_delete = ticket_class.delete
            ticket_class.objects = DummyTicketManager(ticket_class, service, ticket)
            ticket_class.save = dummy
            ticket_class.delete = dummy
            ret = func(*args, **kwds)
            ticket_class.objects = ticket_manager
            ticket_class.save = ticket_save
            ticket_class.delete = ticket_delete
            return ret
        return wrapper
    return decorator


def dummy_proxy(func):
    @functools.wraps(func)
    def wrapper(*args, **kwds):
        proxy_manager = models.Proxy.objects
        models.Proxy.objects = DummyProxyManager()
        ret = func(*args, **kwds)
        models.Proxy.objects = proxy_manager
        return ret
    return wrapper

class DummyProxyManager(object):
    def create(self, **kwargs):
        for field in models.Proxy._meta.fields:
            field.allow_unsaved_instance_assignment = True
        return models.Proxy(**kwargs)

class DummyTicketManager(object):
    def __init__(self, ticket_class, service, ticket):
        self.ticket_class = ticket_class
        self.service = service
        self.ticket = ticket

    def create(self, **kwargs):
        for field in self.ticket_class._meta.fields:
            field.allow_unsaved_instance_assignment = True
        return self.ticket_class(**kwargs)

    def filter(self, *args, **kwargs):
        return DummyQuerySet()

    def get(self, **kwargs):
        for field in self.ticket_class._meta.fields:
            field.allow_unsaved_instance_assignment = True
        if 'value' in kwargs:
            if kwargs['value'] != self.ticket:
                raise self.ticket_class.DoesNotExist()
        else:
            kwargs['value'] = self.ticket
        
        if 'service' in kwargs:
            if kwargs['service'] != self.service:
                raise self.ticket_class.DoesNotExist()
        else:
            kwargs['service'] = self.service
        if not 'user' in kwargs:
            kwargs['user'] = models.User(username="test")
        
        for field in models.ServiceTicket._meta.fields:
            field.allow_unsaved_instance_assignment = True
        for key in list(kwargs):
            if '__' in key:
                del kwargs[key]
        kwargs['attributs'] = {'mail': 'test@example.com'}
        kwargs['service_pattern'] = models.ServicePattern()
        return self.ticket_class(**kwargs)



class DummySession(dict):
    session_key = "test_session"

    def set_expiry(self, int):
        pass

    def flush(self):
        self.clear()


class DummyQuerySet(set):
    pass
