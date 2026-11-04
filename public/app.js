// Centralise les appels API utilisés par la page privée.
import { createSafeImage } from './dom-security.js';

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
const addedProducts = document.querySelector('#added-products');
const addedProductsStatus = document.querySelector('#added-products-status');

let basketSize = 0;

function addToBasket() {
    basketSize += 1;
    cartCount.textContent = basketSize;
}

function bindCartButtons(buttons) {
    buttons.forEach(button => button.addEventListener('click', addToBasket));
}

// Vérifie la session avant d'afficher les informations de l'utilisateur.
async function loadCurrentUser() {
    try {
        const { user } = await request('/api/auth/me');
        userEmail.textContent = user.email;
        await loadAddedFigurines();
    } catch {
        window.location.assign('/login');
    }
}

function createAddedProduct(figurine) {
    const card = document.createElement('article');
    card.className = 'product-card added-product-card';

    const art = document.createElement('div');
    art.className = 'product-art added-product-art';
    const image = createSafeImage(figurine.image_url, `Image de ${figurine.name}`);
    if (image) art.append(image);

    const info = document.createElement('div');
    info.className = 'product-info';
    const category = document.createElement('p');
    category.className = 'product-category';
    category.textContent = figurine.category;
    const name = document.createElement('h3');
    name.textContent = figurine.name;
    const footer = document.createElement('div');
    const price = document.createElement('strong');
    price.textContent = Number(figurine.price).toLocaleString('fr-FR', { style: 'currency', currency: 'EUR' });
    const addButton = document.createElement('button');
    addButton.className = 'add-button';
    addButton.type = 'button';
    addButton.setAttribute('aria-label', `Ajouter ${figurine.name} au panier`);
    addButton.textContent = '+';
    footer.append(price, addButton);
    info.append(category, name, footer);
    card.append(art, info);
    return card;
}

async function loadAddedFigurines() {
    const { figurines } = await request('/api/figurines');
    addedProducts.replaceChildren(...figurines.map(createAddedProduct));
    bindCartButtons(addedProducts.querySelectorAll('.add-button'));
    addedProductsStatus.textContent = figurines.length
        ? `${figurines.length} figurine${figurines.length > 1 ? 's' : ''} ajoutée${figurines.length > 1 ? 's' : ''} récemment.`
        : 'Les prochaines nouveautés apparaîtront ici.';
}

// Supprime le cookie de session puis revient à la page publique.
logoutButton.addEventListener('click', async () => {
    logoutButton.disabled = true;
    await request('/api/auth/logout', { method: 'POST' });
    window.location.assign('/login');
});

bindCartButtons(addButtons);
loadCurrentUser();
