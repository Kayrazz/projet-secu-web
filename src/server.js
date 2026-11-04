import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { createFigurine, findUserByEmail, findUserById, listFigurines } from './db.js';
import { rateLimit } from './rate-limit.js';
import { parseCookies, safeEqual, serializeCookie, signCsrfToken, signJwt, verifyCsrfToken, verifyJwt, verifyPassword } from './security.js';

const root = join(fileURLToPath(new URL('..', import.meta.url)), 'public');
const mimeTypes = { '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.html': 'text/html; charset=utf-8' };

function sendJson(response, status, payload, headers = {}) {
    response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
    response.end(JSON.stringify(payload));
}

function securityHeaders() {
    const headers = {
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https: data:; connect-src 'self'; frame-ancestors 'none'",
        // Interdit l'intégration de la boutique dans une iframe.
        'X-Frame-Options': 'DENY',
        // Empêche le navigateur de deviner un autre type MIME.
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer'
    };

    // HSTS ne doit être envoyé qu'en HTTPS, donc uniquement en production.
    if (config.nodeEnv === 'production') {
        headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
    }

    return headers;
}

async function readJson(request) {
    let body = '';
    for await (const chunk of request) {
        body += chunk;
        if (body.length > 10_000) throw new Error('Payload too large');
    }
    return JSON.parse(body || '{}');
}

function hasValidCsrfToken(request, formToken) {
    const headerToken = request.headers['x-csrf-token'];
    return Boolean(formToken && headerToken)
        && safeEqual(formToken, headerToken)
        && verifyCsrfToken(formToken, config.jwtSecret);
}

function authenticatedUser(request) {
    const token = parseCookies(request)[config.cookieName];
    if (!token) return null;
    try {
        const claims = verifyJwt(token, config.jwtSecret);
        return findUserById(Number(claims.sub));
    } catch {
        return null;
    }
}

function authenticatedAdmin(request) {
    const user = authenticatedUser(request);
    return user?.role === 'admin' ? user : null;
}

function isValidImageUrl(value) {
    try {
        return new URL(value).protocol === 'https:';
    } catch {
        return false;
    }
}

async function handleApi(request, response, url) {
    const headers = securityHeaders();
    if (request.method === 'POST' && url.pathname === '/api/auth/login') {
        try {
            const { csrfToken, email, password } = await readJson(request);
            // Le token vient du champ hidden et doit aussi être envoyé par un header personnalisé.
            if (!hasValidCsrfToken(request, csrfToken)) return sendJson(response, 403, { error: 'Jeton CSRF invalide.' }, headers);
            const limiter = rateLimit(`login:${request.socket.remoteAddress || 'unknown'}`);
            if (!limiter.allowed) return sendJson(response, 429, { error: 'Trop de tentatives. Réessayez plus tard.' }, { ...headers, 'Retry-After': limiter.retryAfter });
            const normalizedEmail = String(email || '').trim().toLowerCase();
            const user = findUserByEmail(normalizedEmail);
            if (!user || !(await verifyPassword(String(password || ''), user.password_hash))) return sendJson(response, 401, { error: 'Identifiants invalides.' }, headers);
            const token = signJwt({ sub: String(user.id), role: user.role }, config.jwtSecret, config.tokenTtlSeconds);
            return sendJson(response, 200, { user: { id: user.id, email: user.email, role: user.role } }, { ...headers, 'Set-Cookie': serializeCookie(config.cookieName, token, { maxAge: config.tokenTtlSeconds, secure: config.nodeEnv === 'production' }) });
        } catch {
            return sendJson(response, 400, { error: 'Requête JSON invalide.' }, headers);
        }
    }
    if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
        return sendJson(response, 200, { ok: true }, { ...headers, 'Set-Cookie': serializeCookie(config.cookieName, '', { maxAge: 0, secure: config.nodeEnv === 'production' }) });
    }
    if (request.method === 'GET' && url.pathname === '/api/auth/me') {
        const user = authenticatedUser(request);
        return user ? sendJson(response, 200, { user }, headers) : sendJson(response, 401, { error: 'Authentification requise.' }, headers);
    }
    if (request.method === 'GET' && url.pathname === '/api/figurines') {
        return sendJson(response, 200, { figurines: listFigurines() }, headers);
    }
    if (url.pathname === '/api/admin/figurines') {
        if (!authenticatedUser(request)) return sendJson(response, 401, { error: 'Authentification requise.' }, headers);
        if (!authenticatedAdmin(request)) return sendJson(response, 403, { error: 'Accès administrateur requis.' }, headers);
        if (request.method === 'GET') return sendJson(response, 200, { figurines: listFigurines() }, headers);
        if (request.method === 'POST') {
            try {
                const { csrfToken, name, category, imageUrl, price } = await readJson(request);
                if (!hasValidCsrfToken(request, csrfToken)) return sendJson(response, 403, { error: 'Jeton CSRF invalide.' }, headers);
                const cleanName = String(name || '').trim();
                const cleanCategory = String(category || '').trim();
                const cleanImageUrl = String(imageUrl || '').trim();
                const priceNumber = Number(String(price ?? '').replace(',', '.'));
                if (!cleanName || cleanName.length > 120 || !cleanCategory || cleanCategory.length > 80 || !isValidImageUrl(cleanImageUrl) || cleanImageUrl.length > 500 || !Number.isFinite(priceNumber) || priceNumber < 0 || priceNumber > 100000) {
                    return sendJson(response, 400, { error: 'Nom, catégorie ou URL d’image invalide.' }, headers);
                }
                return sendJson(response, 201, { figurine: createFigurine({ name: cleanName, category: cleanCategory, imageUrl: cleanImageUrl, price: priceNumber }) }, headers);
            } catch {
                return sendJson(response, 400, { error: 'Requête JSON invalide.' }, headers);
            }
        }
        return sendJson(response, 405, { error: 'Méthode non autorisée.' }, { ...headers, Allow: 'GET, POST' });
    }
    if (request.method === 'GET' && url.pathname === '/api/lab/broken-auth') {
        if (!config.enableBrokenAuthLab) return sendJson(response, 404, { error: 'Lab désactivé.' }, headers);
        const requestedUserId = Number(url.searchParams.get('userId'));
        const user = findUserById(requestedUserId);
        return user ? sendJson(response, 200, { warning: 'Démo broken authentication : identité contrôlée par le client.', user }, headers) : sendJson(response, 404, { error: 'Utilisateur introuvable.' }, headers);
    }
    return sendJson(response, 404, { error: 'Route API introuvable.' }, headers);
}

async function serveStatic(request, response, url) {
    const headers = securityHeaders();

    // Le backoffice est protégé avant même de servir son document HTML.
    if (url.pathname === '/admin') {
        const user = authenticatedUser(request);
        if (!user) return response.writeHead(401, headers).end('Authentification requise.');
        if (user.role !== 'admin') return response.writeHead(403, headers).end('Accès administrateur requis.');
    }

    // Chaque écran possède son propre document HTML.
    const pages = {
        '/': '/login.html',
        '/login': '/login.html',
        '/app': '/app.html',
        '/admin': '/admin.html'
    };
    const requested = pages[url.pathname] || url.pathname;
    let filePath = normalize(join(root, requested));
    if (!filePath.startsWith(root)) return response.writeHead(403, headers).end();
    try {
        let file;
        try {
            file = await stat(filePath);
        } catch {
            filePath = join(root, 'index.html');
            file = await stat(filePath);
        }
        if (!file.isFile()) throw new Error('Not a file');
        const responseHeaders = { 'Content-Type': mimeTypes[extname(filePath)] || 'application/octet-stream', ...headers };
        response.writeHead(200, responseHeaders);
        if (url.pathname === '/' || url.pathname === '/login' || url.pathname === '/admin') {
            const html = await readFile(filePath, 'utf8');
            return response.end(html.replace('{{CSRF_TOKEN}}', signCsrfToken(config.jwtSecret, config.tokenTtlSeconds)));
        }
        createReadStream(filePath).pipe(response);
    } catch {
        response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', ...headers }).end('Not found');
    }
}

const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    if (url.pathname.startsWith('/api/')) return handleApi(request, response, url);
    if (request.method !== 'GET') return response.writeHead(405, { Allow: 'GET', ...securityHeaders() }).end();
    return serveStatic(request, response, url);
});

server.listen(config.port, () => console.log(`Shop server running at http://localhost:${config.port}`));
