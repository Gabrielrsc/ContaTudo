from django.urls import path
from apps.usuarios.views import login, cadastro, resetSenha

urlpatterns = [
        path('', login, name='login'),
        path('cadastrar/', cadastro, name='cadastro'),
        path('reset-senha/', resetSenha, name='resetSenha')
]
