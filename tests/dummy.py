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

class DummyTicketManager(object):
    def __init__(self, ticket_class, service, ticket):
        self.ticket_class = ticket_class
        self.service = service
        self.ticket = ticket

    def create(self, **kwargs):
        for field in models.ServiceTicket._meta.fields:
            field.allow_unsaved_instance_assignment = True
        return self.ticket_class(**kwargs)

    def filter(self, *args, **kwargs):
        return DummyQuerySet()

    def get(self, **kwargs):
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
        for key in kwargs.keys():
            if '__' in key:
                del kwargs[key]
        kwargs['attributs'] = {'mail': 'test@example.com'}
        kwargs['service_pattern'] = models.ServicePattern()
        return self.ticket_class(**kwargs)



class DummySession(dict):
    session_key = "test_session"

    def set_expiry(self, int):
        pass


class DummyQuerySet(set):
    pass
