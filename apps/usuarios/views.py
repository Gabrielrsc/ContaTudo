from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import auth
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib import messages


def login(request):
    if request.method == "POST":
        email = request.POST.get('email')
        senha = request.POST.get('senha')

        # Busca o usuário pelo e-mail
        try:
            user = User.objects.get(email=email)
            usuario = auth.authenticate(request, username=user.username, password=senha)
            
            if usuario is not None:
                auth.login(request, usuario)
                success_message = f'{user.first_name} logado com sucesso!'
                return render(request, 'usuarios/reset-senha.html', {'success_message': success_message})
            else:
                error = 'Erro ao efetuar login. Verifique suas credenciais.'
                return render(request, 'usuarios/index.html', {'error': error})

        except User.DoesNotExist:
            error = 'Usuário não encontrado.'
            return render(request, 'usuarios/index.html', {'error': error})

    return render(request, 'usuarios/index.html')

def cadastro(request):
    if request.method == "POST":
        first_name = request.POST.get('first_name')
        email = request.POST.get('email')
        senha = request.POST.get('senha')
        confirmar_senha = request.POST.get('confirm_password')

        # Verificação de campos obrigatórios
        if not all([first_name, email, senha, confirmar_senha]):
            return render(request, 'usuarios/cadastro.html', {'form_error': 'Preencha todos os campos obrigatórios'})
        
        # Validação do e-mail
        if not validar_email(email):
            return render(request, 'usuarios/cadastro.html', {'email_error': 'E-mail inválido'})
        
        # Verificação de e-mail já existente
        if User.objects.filter(email=email).exists():
            return render(request, 'usuarios/cadastro.html', {'email_error': 'Já existe um usuário com esse e-mail'})
        
        # Validação da senha
        error_message = validar_senha(senha, confirmar_senha)
        if error_message:
            return render(request, 'usuarios/cadastro.html', {'password_error': error_message})

        # Criação do usuário
        User.objects.create_user(username=email, first_name=first_name, email=email, password=senha)
        messages.success(request, 'Usuário cadastrado com sucesso. Faça login para continuar.')
        return redirect('login')

    return render(request, 'usuarios/cadastro.html')


def validar_email(email):
    try:
        validate_email(email)
        return True
    except ValidationError:
        return False

def validar_senha(senha, confirmar_senha):
    if len(senha) < 8:
        return 'A senha deve ter pelo menos 8 caracteres'
    if not any(char.isdigit() for char in senha):
        return 'A senha deve conter pelo menos um número'
    if not any(char.isupper() for char in senha):
        return 'A senha deve conter pelo menos uma letra maiúscula'
    if senha != confirmar_senha:
        return 'As senhas não coincidem'
    return None

def resetSenha(request):
    return render(request, 'usuarios/reset-senha.html')
