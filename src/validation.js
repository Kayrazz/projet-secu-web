// Vérifie une adresse avec une partie locale, un domaine et une extension d'au moins deux caractères.
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
// Autorise les caractères alphanumériques, espaces et ponctuation métier, sans balises ni caractères de contrôle.
const catalogTextPattern = /^[\p{L}\p{N}][\p{L}\p{N} &'’.,()/-]*$/u;

export function normalizeEmail(value) {
    return String(value ?? '').trim().toLowerCase();
}

export function isValidEmail(value) {
    const email = normalizeEmail(value);
    return email.length <= 254 && emailPattern.test(email);
}

export function isValidPassword(value) {
    const password = String(value ?? '');
    return password.length >= 8 && password.length <= 128;
}

export function cleanCatalogText(value, maxLength) {
    const text = String(value ?? '').trim();
    return text.length > 0
        && text.length <= maxLength
        && catalogTextPattern.test(text)
        ? text
        : null;
}

export function parsePrice(value) {
    const rawPrice = String(value ?? '').trim().replace(',', '.');
    // Accepte un prix positif avec au plus six chiffres et deux décimales.
    if (!/^(?:\d{1,6})(?:\.\d{1,2})?$/.test(rawPrice)) return null;

    const price = Number(rawPrice);
    return Number.isFinite(price) && price >= 0 && price <= 100000 ? price : null;
}

export function parsePositiveInteger(value) {
    const rawValue = String(value ?? '');
    // Accepte uniquement les entiers positifs écrits sans signe ni décimale.
    if (!/^[1-9]\d*$/.test(rawValue)) return null;

    const integer = Number(rawValue);
    return Number.isSafeInteger(integer) ? integer : null;
}
