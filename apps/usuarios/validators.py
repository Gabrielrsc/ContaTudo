from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth.models import User

def validar_email(email):
    try:
        validate_email(email)
    except ValidationError:
        raise ValidationError("E-mail inválido")
    
    if User.objects.filter(email=email).exists():
        raise ValidationError("Já existe um usuário com esse e-mail")

def validar_senha(senha, confirmar_senha):
    if len(senha) < 8:
        raise ValidationError("A senha deve ter pelo menos 8 caracteres")
    
    if not any(char.isdigit() for char in senha):
        raise ValidationError("A senha deve conter pelo menos um número")
    
    if not any(char.isupper() for char in senha):
        raise ValidationError("A senha deve conter pelo menos uma letra maiúscula")
    
    if senha != confirmar_senha:
        raise ValidationError("As senhas não coincidem")
