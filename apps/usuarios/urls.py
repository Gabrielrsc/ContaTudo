from django.urls import path
from django.contrib.auth import views as auth_views
from apps.usuarios.views import login, cadastro
from .views import CustomPasswordResetConfirmView  # Importando a view personalizada
urlpatterns = [
    path('', login, name='login'),
    path('cadastrar/', cadastro, name='cadastro'),
    
    # Rotas para redefinição de senha
    path('reset_senha/', auth_views.PasswordResetView.as_view(
        template_name='usuarios/reset_senha.html',
        email_template_name='usuarios/email_reset_senha.html',
        success_url='done/'
    ), name='resetSenha'), 

    path('reset_senha/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='usuarios/reset_senha_done.html'
    ), name='password_reset_done'),

    path('reset-password-confirm/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(
        template_name='usuarios/reset_senha_confirm.html'
    ), name='password_reset_confirm'),

    path('reset-password-complete/', auth_views.PasswordResetCompleteView.as_view(
        template_name='usuarios/reset_senha_complete.html'
    ), name='password_reset_complete'),
]