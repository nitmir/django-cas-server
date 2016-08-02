from django import template
from django import forms

register = template.Library()


@register.filter(name='is_checkbox')
def is_checkbox(field):
    return isinstance(field.field.widget, forms.CheckboxInput)


@register.filter(name='is_hidden')
def is_hidden(field):
    return isinstance(field.field.widget, forms.HiddenInput)
