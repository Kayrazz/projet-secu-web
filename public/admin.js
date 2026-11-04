// Le backoffice utilise la même session JWT que la boutique.
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

const form = document.querySelector('#figurine-form');
const formMessage = document.querySelector('#form-message');
const submitButton = form.querySelector('button[type="submit"]');
const list = document.querySelector('#figurine-list');
const emptyList = document.querySelector('#empty-list');
const figurineCount = document.querySelector('#figurine-count');
const logoutButton = document.querySelector('#logout');

function readCsrfToken() {
    return form.elements.csrf_token.value;
}

function createCell(text, className = '') {
    const cell = document.createElement('td');
    cell.textContent = text;
    if (className) cell.className = className;
    return cell;
}

// Construit les lignes avec textContent pour ne jamais injecter les données produit en HTML.
function renderFigurines(figurines) {
    list.replaceChildren();
    emptyList.hidden = figurines.length > 0;
    figurineCount.textContent = figurines.length;

    figurines.forEach(figurine => {
        const row = document.createElement('tr');
        const imageCell = document.createElement('td');
        const image = document.createElement('img');
        image.className = 'figurine-thumb';
        image.src = figurine.image_url;
        image.alt = `Image de ${figurine.name}`;
        image.loading = 'lazy';
        imageCell.append(image);

        row.append(imageCell);
        row.append(createCell(figurine.name, 'figurine-name'));
        row.append(createCell(figurine.category));
        row.append(createCell(Number(figurine.price).toLocaleString('fr-FR', { style: 'currency', currency: 'EUR' })));
        row.append(createCell(new Date(figurine.created_at).toLocaleDateString('fr-FR')));
        list.append(row);
    });
}

async function loadFigurines() {
    const { figurines } = await request('/api/admin/figurines');
    renderFigurines(figurines);
}

async function loadAdminSession() {
    try {
        const { user } = await request('/api/auth/me');
        if (user.role !== 'admin') throw new Error('Accès administrateur requis.');
        await loadFigurines();
    } catch {
        window.location.assign('/app');
    }
}

// Crée une figurine avec le token CSRF présent dans le formulaire.
form.addEventListener('submit', async event => {
    event.preventDefault();
    formMessage.textContent = '';
    submitButton.disabled = true;

    const formData = new FormData(form);
    const payload = {
        csrfToken: formData.get('csrf_token'),
        name: formData.get('name'),
        category: formData.get('category'),
        imageUrl: formData.get('image_url'),
        price: formData.get('price')
    };

    try {
        await request('/api/admin/figurines', {
            method: 'POST',
            headers: { 'X-CSRF-Token': readCsrfToken() },
            body: JSON.stringify(payload)
        });
        form.reset();
        form.elements.csrf_token.value = payload.csrfToken;
        formMessage.textContent = 'Figurine ajoutée au catalogue.';
        await loadFigurines();
    } catch (error) {
        formMessage.textContent = error.message;
    } finally {
        submitButton.disabled = false;
    }
});

logoutButton.addEventListener('click', async () => {
    await request('/api/auth/logout', { method: 'POST' });
    window.location.assign('/login');
});

loadAdminSession();
