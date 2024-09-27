from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import auth
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.views import PasswordResetView
from django.core.mail import send_mail
from django.conf import settings
from django.http import HttpResponse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.password_validation import validate_password
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from apps.usuarios.validators import validar_email, validate_email, validar_senha, ValidationError
from django.contrib.auth.views import PasswordResetConfirmView
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib import messages
from django.contrib.auth.password_validation import validate_password
    
class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'usuarios/reset_senha_confirm.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['uidb64'] = self.kwargs['uidb64']
        context['token'] = self.kwargs['token']
        return context

def login(request):
    if request.method == "POST":
        email = request.POST.get('email')
        senha = request.POST.get('senha')

        try:
            user = User.objects.get(email=email)
            usuario = auth.authenticate(request, username=user.username, password=senha)
            
            if usuario is not None:
                auth.login(request, usuario)
                messages.success(request, f'{user.first_name} logado com sucesso!')
                return redirect('resetSenha')  
            else:
                messages.error(request, 'Erro ao efetuar login. Verifique suas credenciais.')
        except User.DoesNotExist:
            messages.error(request, 'Usuário não encontrado.')

    return render(request, 'usuarios/index.html')


def cadastro(request):
    if request.method == "POST":
        first_name = request.POST.get('first_name')
        email = request.POST.get('email')
        senha = request.POST.get('senha')
        confirmar_senha = request.POST.get('confirm_password')

        if not all([first_name, email, senha, confirmar_senha]):
            messages.error(request, 'Preencha todos os campos obrigatórios')
            return redirect('cadastro')

        if not validar_email(email):
            messages.error(request, 'E-mail inválido')
            return redirect('cadastro')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Já existe um usuário com esse e-mail')
            return redirect('cadastro')

        error_message = validar_senha(senha, confirmar_senha)
        if error_message:
            messages.error(request, error_message)
            return redirect('cadastro')

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
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            subject = 'Redefinição de Senha'
            message = f'Siga o link para redefinir sua senha: http://127.0.0.1:8000/reset-senha-confirm/{user.id}/'  # Ajuste o link conforme necessário
            send_mail(subject, message, settings.EMAIL_HOST_USER, [email])
            return HttpResponse("E-mail de redefinição de senha enviado com sucesso!")
        except User.DoesNotExist:
            return HttpResponse("Usuário não encontrado.")
        
    return render(request, 'usuarios/reset_senha.html') 

def recuperar_senha(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        
        # Aqui você pode adicionar lógica para verificar se o e-mail existe no banco de dados
        # Exemplo: user = User.objects.filter(email=email).first()
        
        if email:  # Verifique se o e-mail é válido
            # Enviar e-mail
            subject = 'Recuperação de Senha'
            message = 'Aqui está o seu código de recuperação de senha.'  # Substitua por um código gerado, se necessário
            from_email = settings.EMAIL_HOST_USER
            
            try:
                send_mail(subject, message, from_email, [email])
                messages.success(request, 'Um código de recuperação foi enviado para o seu e-mail.')
                return redirect('login')  # Redireciona para a página de login ou outra que você desejar
            except Exception as e:
                messages.error(request, f'Erro ao enviar o e-mail: {e}')
        else:
            messages.error(request, 'Por favor, insira um e-mail válido.')
    
    return render(request, 'usuarios/recuperar_senha.html')

def solicitar_redefinicao_senha(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            subject = 'Redefinição de Senha'
            message = f'Siga o link para redefinir sua senha: http://127.0.0.1:8000/reset-senha-confirm/{user.id}/'  # Ajuste o link conforme necessário
            send_mail(subject, message, settings.EMAIL_HOST_USER, [email])
            return HttpResponse("E-mail de redefinição de senha enviado com sucesso!")
        except User.DoesNotExist:
            return HttpResponse("Usuário não encontrado.")

    return render(request, 'usuarios/reset_senha.html')  # Altere para reset_senha.html

class CustomPasswordResetView(PasswordResetView):
    template_name = 'usuarios/reset_senha.html'
    email_template_name = 'usuarios/email_reset_senha.html'  # Crie este template para o email
    subject_template_name = 'usuarios/email_subject.txt'  # Crie este template para o assunto do email
    success_url = 'usuarios/password_reset_done/'  # Redireciona após o envio do email
    
def resetSenha(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            subject = 'Redefinição de Senha'
            message = f'Siga o link para redefinir sua senha: http://127.0.0.1:8000/reset-senha-confirm/{uid}/{token}/'
            send_mail(subject, message, settings.EMAIL_HOST_USER, [email])
            messages.success(request, 'E-mail de redefinição de senha enviado com sucesso!')
        except User.DoesNotExist:
            messages.error(request, 'Usuário não encontrado.')

    return render(request, 'usuarios/reset_senha.html')

def resetar_senha(request, uid, token):
    try:
        user_id = force_str(urlsafe_base64_decode(uid))
        usuario = User.objects.get(pk=user_id)

        if request.method == 'POST':
            nova_senha = request.POST.get('nova_senha')
            confirmar_senha = request.POST.get('confirmar_senha')

            if nova_senha != confirmar_senha:
                messages.error(request, 'As senhas não coincidem.')
                return render(request, 'usuarios/resetar_senha.html', {'uid': uid, 'token': token})

            # Verificar requisitos da senha usando as validações do Django
            try:
                validate_password(nova_senha, usuario)
            except Exception as e:
                messages.error(request, f'Erro de validação de senha: {", ".join(e.messages)}')
                return render(request, 'usuarios/resetar_senha.html', {'uid': uid, 'token': token})

            if default_token_generator.check_token(usuario, token):
                usuario.set_password(nova_senha)  # Altera a senha corretamente
                usuario.save()
                messages.success(request, 'Senha redefinida com sucesso!')
                return redirect('login')
            else:
                messages.error(request, 'O link de redefinição de senha é inválido ou expirou.')

    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        messages.error(request, 'O link de redefinição de senha é inválido ou expirou.')

    return render(request, 'usuarios/resetar_senha.html', {'uid': uid, 'token': token})
    
def test_email(request):
    subject = 'Testando E-mail'
    message = 'Este é um e-mail de teste.'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = ['gabrielrobertson.s@gmail.com']

    try:
        send_mail(subject, message, from_email, recipient_list)
        return HttpResponse("E-mail enviado com sucesso!")
    except Exception as e:
        return HttpResponse(f"Erro ao enviar e-mail: {e}")
    
from django.contrib.auth.views import PasswordResetConfirmView
from django.urls import reverse_lazy

class DefinirNovaSenhaView(PasswordResetConfirmView):
    template_name = 'definir_nova_senha.html'
    success_url = reverse_lazy('login')



def redefinir_senha(request, uidb64, token):
    """
    View para redefinir a senha depois que o usuário clicar no link recebido por e-mail.
    """
    try:
        # Decodifica o uidb64 e obtém o ID do usuário
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        messages.error(request, 'O link de redefinição de senha é inválido.')
        return redirect('login')

    # Verifica se o token é válido para o usuário
    if not default_token_generator.check_token(user, token):
        messages.error(request, 'O link de redefinição de senha é inválido ou expirou.')
        return redirect('login')

    if request.method == 'POST':
        nova_senha = request.POST.get('nova_senha')
        confirmar_senha = request.POST.get('confirmar_senha')

        # Verifica se as senhas inseridas coincidem
        if nova_senha != confirmar_senha:
            messages.error(request, 'As senhas não coincidem. Por favor, tente novamente.')
            return render(request, 'usuarios/reset_senha_confirm.html', {'uidb64': uidb64, 'token': token})

        # Verifica a complexidade da senha usando as validações padrão do Django
        try:
            validate_password(nova_senha, user)
        except ValidationError as e:
            messages.error(request, f'Erro de validação de senha: {", ".join(e.messages)}')
            return render(request, 'usuarios/reset_senha_confirm.html', {'uidb64': uidb64, 'token': token})

        # Atualiza a senha do usuário e salva no banco de dados
        user.set_password(nova_senha)
        user.save()

        # Mensagem de sucesso e redirecionamento
        messages.success(request, 'Sua senha foi redefinida com sucesso! Agora você pode fazer login usando sua nova senha.')
        return redirect('login')

    return render(request, 'usuarios/reset_senha_confirm.html', {'uidb64': uidb64, 'token': token})



from django.contrib.auth.views import PasswordResetConfirmView
from django.urls import reverse_lazy
from django.contrib.auth.forms import SetPasswordForm

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'usuarios/reset_senha_confirm.html'
    success_url = reverse_lazy('password_reset_complete')
    form_class = SetPasswordForm
    
    
    
    
import logging

logger = logging.getLogger(__name__)

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    def form_valid(self, form):
        logger.info("Formulário de redefinição de senha válido. Iniciando redefinição...")
        user = form.save()
        logger.info(f"Senha redefinida com sucesso para o usuário: {user}")
        return super().form_valid(form)
    
def dispatch(self, *args, **kwargs):
    self.user = self.get_user(kwargs['uidb64'])
    if not default_token_generator.check_token(self.user, kwargs['token']):
        logger.warning("Token de redefinição de senha inválido ou expirado.")
        return self.render_to_response({'token_invalid': True})
    return super().dispatch(*args, **kwargs)