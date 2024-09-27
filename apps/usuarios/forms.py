# apps/usuarios/forms.py

from django import forms
from typing import Any
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

class RecuperarSenhaForm(forms.Form):
    email = forms.EmailField(
        label='E-mail',
        max_length=254,
        widget=forms.EmailInput(attrs={
            'placeholder': 'Digite seu e-mail',
            'class': 'input',  # Adicione classes CSS se necessário
            'required': 'required'  # Torna o campo obrigatório
        }),
        error_messages={
            'required': _('Por favor, insira seu e-mail.'),
            'invalid': _('Endereço de e-mail inválido.'),
        }
    )

    def clean_email(self):
        email = self.cleaned_data.get('email')
        # Aqui você pode adicionar lógica para verificar se o e-mail existe no banco de dados
        # Exemplo:
        if not User.objects.filter(email=email).exists():
            raise ValidationError(_('Esse e-mail não está cadastrado.'))
        return email
