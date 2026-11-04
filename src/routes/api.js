import { join } from 'node:path';
import { createFigurine, findUserByEmail, findUserById, listFigurines } from '../db.js';
import { rateLimit } from '../rate-limit.js';
import { safeEqual, serializeCookie, signJwt, verifyCsrfToken, verifyPassword } from '../security.js';
import { isSafeOutboundUrl } from '../ssrf.js';
import { saveUploadedImage } from '../upload.js';
import { getClientIp, logger } from '../logger.js';
import {
    cleanCatalogText,
    isValidEmail,
    isValidPassword,
    normalizeEmail,
    parsePositiveInteger,
    parsePrice
} from '../validation.js';

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
        const clientKey = getClientIp(request);
        const apiLimiter = rateLimit(`api:${clientKey}`, config.apiRateLimit, config.apiRateLimitWindowMs);

        if (!apiLimiter.allowed) {
            logger.warn('api.rate_limited', { ip: clientKey, method: request.method, route: url.pathname });
            return sendJson(response, 429, { error: 'Trop de requêtes. Réessayez plus tard.' }, {
                ...responseHeaders,
                'Retry-After': apiLimiter.retryAfter
            });
        }

        if (request.method === 'POST' && url.pathname === '/api/auth/login') {
            return login(request, response, responseHeaders, config, clientKey);
        }

        if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
            logger.info('auth.logout', { ip: clientKey });
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
            const requestedUserId = parsePositiveInteger(url.searchParams.get('userId'));
            if (requestedUserId === null) return sendJson(response, 400, { error: 'Identifiant utilisateur invalide.' }, responseHeaders);
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
            logger.warn('auth.csrf_rejected', { ip: clientKey });
            return sendJson(response, 403, { error: 'Jeton CSRF invalide.' }, headers);
        }

        const limiter = rateLimit(`login:${clientKey}`, config.loginRateLimit, config.loginRateLimitWindowMs);
        if (!limiter.allowed) {
            logger.warn('auth.login_rate_limited', { ip: clientKey });
            return sendJson(response, 429, { error: 'Trop de tentatives. Réessayez plus tard.' }, {
                ...headers,
                'Retry-After': limiter.retryAfter
            });
        }

        const normalizedEmail = normalizeEmail(email);
        if (!isValidEmail(normalizedEmail) || !isValidPassword(password)) {
            return sendJson(response, 400, { error: 'Adresse email ou mot de passe invalide.' }, headers);
        }
        const user = findUserByEmail(normalizedEmail);
        const passwordIsValid = user && await verifyPassword(password, user.password_hash);
        if (!passwordIsValid) {
            logger.warn('auth.login_failed', { ip: clientKey, reason: 'invalid_credentials' });
            return sendJson(response, 401, { error: 'Identifiants invalides.' }, headers);
        }

        const token = signJwt({ sub: String(user.id), role: user.role }, config.jwtSecret, config.tokenTtlSeconds);
        const cookie = serializeCookie(config.cookieName, token, {
            maxAge: config.tokenTtlSeconds,
            secure: config.nodeEnv === 'production'
        });
        logger.info('auth.login_succeeded', { ip: clientKey, role: user.role });
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
        const cleanName = cleanCatalogText(name, 120);
        const cleanCategory = cleanCatalogText(category, 80);
        const cleanImageUrl = String(imageUrl || '').trim();
        const priceNumber = parsePrice(price);
        const validImage = isStoredImagePath(cleanImageUrl) || await isSafeOutboundUrl(cleanImageUrl);
        const invalid = !cleanName || !cleanCategory || !validImage || cleanImageUrl.length > 500 || priceNumber === null;
        if (invalid) return sendJson(response, 400, { error: 'Nom, catégorie, prix ou URL d’image invalide.' }, headers);
        const figurine = createFigurine({ name: cleanName, category: cleanCategory, imageUrl: cleanImageUrl, price: priceNumber });
        logger.info('admin.figurine_created', { ip: getClientIp(request), category: cleanCategory, price: priceNumber });
        return sendJson(response, 201, { figurine }, headers);
    } catch {
        return sendJson(response, 400, { error: 'Requête JSON invalide.' }, headers);
    }
}

async function uploadImage(request, response, headers, config, root) {
    try {
        if (!verifyCsrfToken(request.headers['x-csrf-token'], config.jwtSecret)) return sendJson(response, 403, { error: 'Jeton CSRF invalide.' }, headers);
        const upload = await saveUploadedImage(request, join(root, 'uploads'), config.maxUploadBytes);
        logger.info('admin.upload_succeeded', { ip: getClientIp(request), mimeType: upload.mimeType, size: upload.size });
        return sendJson(response, 201, { imageUrl: upload.imageUrl, size: upload.size, mimeType: upload.mimeType }, headers);
    } catch (error) {
        logger.warn('admin.upload_rejected', { ip: getClientIp(request), reason: error.message });
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
