import default_settings

from django import forms
from django.conf import settings

import models

class UserCredential(forms.Form):
    username = forms.CharField(label='login')
    service = forms.CharField(widget=forms.HiddenInput(), required=False)
    password = forms.CharField(label='password', widget=forms.PasswordInput)
    method = forms.CharField(widget=forms.HiddenInput(), required=False)
    warn = forms.BooleanField(label='warn', required=False)

    def __init__(self, *args, **kwargs):
        super(UserCredential, self).__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super(UserCredential, self).clean()
        auth = settings.CAS_AUTH_CLASS(cleaned_data.get("username"))
        if auth.test_password(cleaned_data.get("password")):
            try:
                user = models.User.objects.get(username=auth.username)
                user.attributs=auth.attributs()
                user.save()
            except models.User.DoesNotExist:
                user = models.User.objects.create(username=auth.username, attributs=auth.attributs())
                user.save()
            self.user = user
        else:
            raise forms.ValidationError("Bad user")


class TicketForm(forms.ModelForm):
    class Meta:
        model = models.Ticket
        exclude = []
    service = forms.CharField(widget=forms.TextInput)
