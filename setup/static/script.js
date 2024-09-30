document.addEventListener("DOMContentLoaded", () => {
    const messageElement = document.querySelector('.message');
    
    if (messageElement) {
        messageElement.classList.add('show'); // Adiciona a classe 'show' ao carregar

        setTimeout(() => {
            messageElement.classList.add('hide'); // Adiciona a classe de ocultação
        }, 3000); // 3 segundos

        messageElement.addEventListener('transitionend', (event) => {
            if (messageElement.classList.contains('hide')) {
                messageElement.classList.add('hidden'); // Adiciona a classe 'hidden'
            }
        });
    }
});

document.getElementById('togglePassword').addEventListener('click', function() {
    const passwordInput = document.getElementById('id_new_password1');
    const passwordType = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', passwordType);
    
    // Trocar o ícone
    this.querySelector('i').classList.toggle('fa-eye');
    this.querySelector('i').classList.toggle('fa-eye-slash');

    // Remove o foco do botão
    this.blur();
});

document.getElementById('toggleConfirmPassword').addEventListener('click', function() {
    const confirmPasswordInput = document.getElementById('id_new_password2');
    const confirmPasswordType = confirmPasswordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    confirmPasswordInput.setAttribute('type', confirmPasswordType);
    
    // Trocar o ícone
    this.querySelector('i').classList.toggle('fa-eye');
    this.querySelector('i').classList.toggle('fa-eye-slash');

    // Remove o foco do botão
    this.blur();
});



const form = document.getElementById('cadastro-form');
const submitBtn = document.getElementById('submit-btn');
    
    form.addEventListener('submit', () => {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Processando...';
    });

    document.addEventListener('DOMContentLoaded', function() {
        const message = document.querySelector('.message');
        if (message) {
            message.classList.add('show');
            
            // Esconder a mensagem automaticamente após 3 segundos
            setTimeout(() => {
                message.classList.remove('show');
                message.classList.add('hide');
                
                // Remover o elemento da DOM após a transição
                setTimeout(() => {
                    message.classList.add('hidden');
                }, 500); // Espera a transição de 0.5s para ocultar
            }, 3000); // Mensagem visível por 3 segundos
        }
    });