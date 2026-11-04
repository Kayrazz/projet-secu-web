// Centralise les appels API utilisés par la page de connexion.
async function request(path, options = {}) {
    const response = await fetch(path, {
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        },
        ...options
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Une erreur est survenue.');
    return data;
}

const form = document.querySelector('#login-form');
const errorMessage = document.querySelector('#login-error');
const submitButton = form.querySelector('button');

// Envoie les identifiants puis laisse le serveur protéger /app.
form.addEventListener('submit', async event => {
    event.preventDefault();
    errorMessage.textContent = '';
    if (!form.reportValidity()) return;
    submitButton.disabled = true;

    const formData = new FormData(form);
    const credentials = {
        csrfToken: formData.get('csrf_token'),
        email: formData.get('email'),
        password: formData.get('password')
    };

    try {
        await request('/api/auth/login', {
            method: 'POST',
            headers: {
                'X-CSRF-Token': credentials.csrfToken
            },
            body: JSON.stringify(credentials)
        });
        window.location.assign('/app');
    } catch (error) {
        errorMessage.textContent = error.message;
        submitButton.disabled = false;
    }
});
