import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const encoder = new TextEncoder();

function base64UrlEncode(value) {
    return Buffer.from(value).toString('base64url');
}

function base64UrlDecode(value) {
    return Buffer.from(value, 'base64url').toString('utf8');
}

export function hashPassword(password) {
    const salt = randomBytes(16).toString('hex');
    const derivedKey = scryptSync(password, salt, 64).toString('hex');
    return `scrypt:${salt}:${derivedKey}`;
}

export function verifyPassword(password, storedHash) {
    const [algorithm, salt, expected] = storedHash.split(':');
    if (algorithm !== 'scrypt' || !salt || !expected) return false;
    const actual = scryptSync(password, salt, 64).toString('hex');
    return timingSafeEqual(encoder.encode(actual), encoder.encode(expected));
}

export function signJwt(payload, secret, ttlSeconds) {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const body = base64UrlEncode(JSON.stringify({ ...payload, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + ttlSeconds }));
    const unsigned = `${header}.${body}`;
    const signature = createHmac('sha256', secret).update(unsigned).digest('base64url');
    return `${unsigned}.${signature}`;
}

export function verifyJwt(token, secret) {
    const [header, body, signature] = token.split('.');
    if (!header || !body || !signature) throw new Error('Invalid token');
    const unsigned = `${header}.${body}`;
    const expected = createHmac('sha256', secret).update(unsigned).digest();
    const actual = Buffer.from(signature, 'base64url');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error('Invalid signature');
    const claims = JSON.parse(base64UrlDecode(body));
    if (claims.exp <= Math.floor(Date.now() / 1000)) throw new Error('Expired token');
    return claims;
}

export function parseCookies(request) {
    const header = request.headers.cookie || '';
    return Object.fromEntries(header.split(';').filter(Boolean).map(part => {
        const index = part.indexOf('=');
        return [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1).trim())];
    }));
}

export function serializeCookie(name, value, options = {}) {
    const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax'];
    if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
    if (options.secure) parts.push('Secure');
    return parts.join('; ');
}
