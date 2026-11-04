import { join } from 'node:path';
import { createFigurine, findUserByEmail, findUserById, listFigurines } from '../db.js';
import { rateLimit } from '../rate-limit.js';
import { safeEqual, serializeCookie, signJwt, verifyCsrfToken, verifyPassword } from '../security.js';
import { isSafeOutboundUrl } from '../ssrf.js';
import { saveUploadedImage } from '../upload.js';

async function readJson(request) {
    let body = '';
    for await (const chunk of request) {
        body += chunk;
        if (body.length > 10_000) throw new Error('Payload too large');
    }
    return JSON.parse(body || '{}');
}

function hasValidCsrfToken(request, formToken, jwtSecret) {
    const headerToken = request.headers['x-csrf-token'];
    return Boolean(formToken && headerToken)
        && safeEqual(formToken, headerToken)
        && verifyCsrfToken(formToken, jwtSecret);
}

function isStoredImagePath(value) {
    return /^\/uploads\/[a-f0-9-]+\.(jpg|png|gif|webp)$/.test(value);
}

export function createApiHandler({ config, headers, authorization, getUser, root }) {
    return async function handleApi(request, response, url) {
        const responseHeaders = headers();
        const clientKey = request.socket.remoteAddress || 'unknown';
        const apiLimiter = rateLimit(`api:${clientKey}`, config.apiRateLimit, config.apiRateLimitWindowMs);

        if (!apiLimiter.allowed) {
            return sendJson(response, 429, { error: 'Trop de requêtes. Réessayez plus tard.' }, {
                ...responseHeaders,
                'Retry-After': apiLimiter.retryAfter
            });
        }

        if (request.method === 'POST' && url.pathname === '/api/auth/login') {
            return login(request, response, responseHeaders, config, clientKey);
        }

        if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
            const cookie = serializeCookie(config.cookieName, '', {
                maxAge: 0,
                secure: config.nodeEnv === 'production'
            });
            return sendJson(response, 200, { ok: true }, { ...responseHeaders, 'Set-Cookie': cookie });
        }

        if (request.method === 'GET' && url.pathname === '/api/auth/me') {
            const user = getUser(request);
            return user
                ? sendJson(response, 200, { user }, responseHeaders)
                : sendJson(response, 401, { error: 'Authentification requise.' }, responseHeaders);
        }

        if (request.method === 'GET' && url.pathname === '/api/figurines') {
            return sendJson(response, 200, { figurines: listFigurines() }, responseHeaders);
        }

        if (url.pathname === '/api/admin/figurines') {
            return authorization.requireRole('admin')(request, response, () => manageFigurines(request, response, responseHeaders, config));
        }

        if (request.method === 'POST' && url.pathname === '/api/admin/uploads') {
            return authorization.requireRole('admin')(request, response, () => uploadImage(request, response, responseHeaders, config, root));
        }

        if (request.method === 'GET' && url.pathname === '/api/lab/broken-auth') {
            if (!config.enableBrokenAuthLab) return sendJson(response, 404, { error: 'Lab désactivé.' }, responseHeaders);
            const requestedUserId = Number(url.searchParams.get('userId'));
            const user = findUserById(requestedUserId);
            return user
                ? sendJson(response, 200, { warning: 'Démo broken authentication : identité contrôlée par le client.', user }, responseHeaders)
                : sendJson(response, 404, { error: 'Utilisateur introuvable.' }, responseHeaders);
        }

        return sendJson(response, 404, { error: 'Route API introuvable.' }, responseHeaders);
    };
}

async function login(request, response, headers, config, clientKey) {
    try {
        const { csrfToken, email, password } = await readJson(request);
        if (!hasValidCsrfToken(request, csrfToken, config.jwtSecret)) {
            return sendJson(response, 403, { error: 'Jeton CSRF invalide.' }, headers);
        }

        const limiter = rateLimit(`login:${clientKey}`, config.loginRateLimit, config.loginRateLimitWindowMs);
        if (!limiter.allowed) {
            return sendJson(response, 429, { error: 'Trop de tentatives. Réessayez plus tard.' }, {
                ...headers,
                'Retry-After': limiter.retryAfter
            });
        }

        const normalizedEmail = String(email || '').trim().toLowerCase();
        const user = findUserByEmail(normalizedEmail);
        const passwordIsValid = user && await verifyPassword(String(password || ''), user.password_hash);
        if (!passwordIsValid) return sendJson(response, 401, { error: 'Identifiants invalides.' }, headers);

        const token = signJwt({ sub: String(user.id), role: user.role }, config.jwtSecret, config.tokenTtlSeconds);
        const cookie = serializeCookie(config.cookieName, token, {
            maxAge: config.tokenTtlSeconds,
            secure: config.nodeEnv === 'production'
        });
        return sendJson(response, 200, { user: { id: user.id, email: user.email, role: user.role } }, {
            ...headers,
            'Set-Cookie': cookie
        });
    } catch {
        return sendJson(response, 400, { error: 'Requête JSON invalide.' }, headers);
    }
}

async function manageFigurines(request, response, headers, config) {
    if (request.method === 'GET') return sendJson(response, 200, { figurines: listFigurines() }, headers);
    if (request.method !== 'POST') return sendJson(response, 405, { error: 'Méthode non autorisée.' }, { ...headers, Allow: 'GET, POST' });

    try {
        const { csrfToken, name, category, imageUrl, price } = await readJson(request);
        if (!hasValidCsrfToken(request, csrfToken, config.jwtSecret)) return sendJson(response, 403, { error: 'Jeton CSRF invalide.' }, headers);
        const cleanName = String(name || '').trim();
        const cleanCategory = String(category || '').trim();
        const cleanImageUrl = String(imageUrl || '').trim();
        const priceNumber = Number(String(price ?? '').replace(',', '.'));
        const validImage = isStoredImagePath(cleanImageUrl) || await isSafeOutboundUrl(cleanImageUrl);
        const invalid = !cleanName || cleanName.length > 120 || !cleanCategory || cleanCategory.length > 80 || !validImage || cleanImageUrl.length > 500 || !Number.isFinite(priceNumber) || priceNumber < 0 || priceNumber > 100000;
        if (invalid) return sendJson(response, 400, { error: 'Nom, catégorie ou URL d’image invalide.' }, headers);
        return sendJson(response, 201, { figurine: createFigurine({ name: cleanName, category: cleanCategory, imageUrl: cleanImageUrl, price: priceNumber }) }, headers);
    } catch {
        return sendJson(response, 400, { error: 'Requête JSON invalide.' }, headers);
    }
}

async function uploadImage(request, response, headers, config, root) {
    try {
        if (!verifyCsrfToken(request.headers['x-csrf-token'], config.jwtSecret)) return sendJson(response, 403, { error: 'Jeton CSRF invalide.' }, headers);
        const upload = await saveUploadedImage(request, join(root, 'uploads'));
        return sendJson(response, 201, { imageUrl: upload.imageUrl, size: upload.size, mimeType: upload.mimeType }, headers);
    } catch (error) {
        const message = error.message === 'Fichier trop volumineux.'
            ? error.message
            : 'Upload refusé : type MIME, contenu ou token invalide.';
        return sendJson(response, 400, { error: message }, headers);
    }
}

function sendJson(response, status, payload, headers = {}) {
    response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
    response.end(JSON.stringify(payload));
}
