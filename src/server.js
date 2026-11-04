import { createReadStream } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from './config.js';
import { createAuthorizationMiddleware, getAuthenticatedUser } from './middleware/authorization.js';
import { createPathTraversalMiddleware } from './middleware/path.js';
import { createApiHandler } from './routes/api.js';
import { signCsrfToken } from './security.js';

const publicDirectory = join(fileURLToPath(new URL('..', import.meta.url)), 'public');

const mimeTypes = {
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.html': 'text/html; charset=utf-8',
    '.jpg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.webp': 'image/webp'
};

function sendJson(response, status, payload, headers = {}) {
    response.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        ...headers
    });
    response.end(JSON.stringify(payload));
}

// Headers communs à toutes les réponses du serveur.
function securityHeaders() {
    const headers = {
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https: data:; connect-src 'self'; frame-src 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer'
    };

    if (config.nodeEnv === 'production') {
        headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
    }

    return headers;
}

const authorization = createAuthorizationMiddleware({
    getUser: request => getAuthenticatedUser(request, config.cookieName, config.jwtSecret),
    deny: (response, status, message) => sendJson(response, status, { error: message }, securityHeaders())
});

const apiHandler = createApiHandler({
    config,
    headers: securityHeaders,
    authorization,
    getUser: request => getAuthenticatedUser(request, config.cookieName, config.jwtSecret),
    root: publicDirectory
});

const pathTraversalMiddleware = createPathTraversalMiddleware(publicDirectory, (response, status, message) => {
    response.writeHead(status, {
        ...securityHeaders(),
        'Content-Type': 'text/plain; charset=utf-8'
    });
    response.end(message);
});

async function serveStatic(request, response, url) {
    if (url.pathname === '/admin') {
        let allowed = false;
        await authorization.requireRole('admin')(request, response, async () => {
            allowed = true;
        });
        if (!allowed) return;
    }

    return pathTraversalMiddleware(request, response, () => serveStaticFile(request, response));
}

async function serveStaticFile(request, response) {
    const pages = {
        '/': '/html/login.html',
        '/login': '/html/login.html',
        '/app': '/html/app.html',
        '/admin': '/html/admin.html'
    };
    const pathname = request.safePathname;
    const requested = pages[pathname] || pathname;
    let filePath = join(publicDirectory, requested);

    try {
        let file;
        try {
            file = await stat(filePath);
        } catch {
            filePath = join(publicDirectory, 'html/index.html');
            file = await stat(filePath);
        }

        if (!file.isFile()) throw new Error('Not a file');
        const headers = {
            'Content-Type': mimeTypes[extname(filePath)] || 'application/octet-stream',
            ...securityHeaders()
        };
        response.writeHead(200, headers);

        if (pathname === '/' || pathname === '/login' || pathname === '/admin') {
            const html = await readFile(filePath, 'utf8');
            return response.end(html.replace('{{CSRF_TOKEN}}', signCsrfToken(config.jwtSecret, config.tokenTtlSeconds)));
        }

        createReadStream(filePath).pipe(response);
    } catch {
        response.writeHead(404, {
            'Content-Type': 'text/plain; charset=utf-8',
            ...securityHeaders()
        });
        response.end('Not found');
    }
}

const server = createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

    if (url.pathname.startsWith('/api/')) {
        return apiHandler(request, response, url);
    }

    if (request.method !== 'GET') {
        return response.writeHead(405, {
            Allow: 'GET',
            ...securityHeaders()
        }).end();
    }

    return serveStatic(request, response, url);
});

server.listen(config.port, () => {
    console.log(`Shop server running at http://localhost:${config.port}`);
});
