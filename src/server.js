import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { findUserByEmail, findUserById } from './db.js';
import { rateLimit } from './rate-limit.js';
import { parseCookies, serializeCookie, signJwt, verifyJwt, verifyPassword } from './security.js';

const root = join(fileURLToPath(new URL('..', import.meta.url)), 'public');
const mimeTypes = { '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.html': 'text/html; charset=utf-8' };

function sendJson(response, status, payload, headers = {}) {
    response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
    response.end(JSON.stringify(payload));
}

function securityHeaders() {
    return {
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
    };
}

async function readJson(request) {
    let body = '';
    for await (const chunk of request) {
        body += chunk;
        if (body.length > 10_000) throw new Error('Payload too large');
    }
    return JSON.parse(body || '{}');
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

async function handleApi(request, response, url) {
    const headers = securityHeaders();
    if (request.method === 'POST' && url.pathname === '/api/auth/login') {
        const limiter = rateLimit(`login:${request.socket.remoteAddress || 'unknown'}`);
        if (!limiter.allowed) return sendJson(response, 429, { error: 'Trop de tentatives. Réessayez plus tard.' }, { ...headers, 'Retry-After': limiter.retryAfter });
        try {
            const { email, password } = await readJson(request);
            const normalizedEmail = String(email || '').trim().toLowerCase();
            const user = findUserByEmail(normalizedEmail);
            if (!user || !verifyPassword(String(password || ''), user.password_hash)) return sendJson(response, 401, { error: 'Identifiants invalides.' }, headers);
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
    if (request.method === 'GET' && url.pathname === '/api/lab/broken-auth') {
        if (!config.enableBrokenAuthLab) return sendJson(response, 404, { error: 'Lab désactivé.' }, headers);
        const requestedUserId = Number(url.searchParams.get('userId'));
        const user = findUserById(requestedUserId);
        return user ? sendJson(response, 200, { warning: 'Démo broken authentication : identité contrôlée par le client.', user }, headers) : sendJson(response, 404, { error: 'Utilisateur introuvable.' }, headers);
    }
    return sendJson(response, 404, { error: 'Route API introuvable.' }, headers);
}

async function serveStatic(response, url) {
    // Chaque écran possède son propre document HTML.
    const pages = {
        '/': '/login.html',
        '/login': '/login.html',
        '/app': '/app.html'
    };
    const requested = pages[url.pathname] || url.pathname;
    let filePath = normalize(join(root, requested));
    if (!filePath.startsWith(root)) return response.writeHead(403).end();
    try {
        let file;
        try {
            file = await stat(filePath);
        } catch {
            filePath = join(root, 'index.html');
            file = await stat(filePath);
        }
        if (!file.isFile()) throw new Error('Not a file');
        response.writeHead(200, { 'Content-Type': mimeTypes[extname(filePath)] || 'application/octet-stream', ...securityHeaders() });
        createReadStream(filePath).pipe(response);
    } catch {
        response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found');
    }
}

const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    if (url.pathname.startsWith('/api/')) return handleApi(request, response, url);
    if (request.method !== 'GET') return response.writeHead(405, { Allow: 'GET' }).end();
    return serveStatic(response, url);
});

server.listen(config.port, () => console.log(`Shop server running at http://localhost:${config.port}`));
