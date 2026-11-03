// Centralise les appels API utilisés par la page privée.
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

const userEmail = document.querySelector('#user-email');
const logoutButton = document.querySelector('#logout');
const cartCount = document.querySelector('#cart-count');
const addButtons = document.querySelectorAll('.add-button');

// Vérifie la session avant d'afficher les informations de l'utilisateur.
async function loadCurrentUser() {
    try {
        const { user } = await request('/api/auth/me');
        userEmail.textContent = user.email;
    } catch {
        window.location.assign('/login');
    }
}

// Supprime le cookie de session puis revient à la page publique.
logoutButton.addEventListener('click', async () => {
    logoutButton.disabled = true;
    await request('/api/auth/logout', { method: 'POST' });
    window.location.assign('/login');
});

loadCurrentUser();

// Le panier est volontairement local pour cette première version de la vitrine.
let basketSize = 0;
addButtons.forEach(button => {
    button.addEventListener('click', () => {
        basketSize += 1;
        cartCount.textContent = basketSize;
    });
});
