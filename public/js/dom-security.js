// Construit une image sans interpréter les données comme du HTML ou du code.
export function createSafeImage(source, alt, className = '') {
    try {
        const imageUrl = new URL(String(source), window.location.origin);
        if (imageUrl.protocol !== 'https:' && imageUrl.origin !== window.location.origin) return null;

        const image = document.createElement('img');
        image.src = imageUrl.href;
        image.alt = String(alt || '');
        image.loading = 'lazy';
        image.referrerPolicy = 'no-referrer';
        if (className) image.className = className;
        return image;
    } catch {
        return null;
    }
}
