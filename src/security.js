import { createHmac, randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCb);
const encoder = new TextEncoder();

function base64UrlEncode(value) {
    return Buffer.from(value).toString('base64url');
}

function base64UrlDecode(value) {
    return Buffer.from(value, 'base64url').toString('utf8');
}

// Hachage asynchrone pour ne pas bloquer l'Event Loop
export async function hashPassword(password) {
    const salt = randomBytes(16).toString('hex');
    const derivedKey = await scrypt(password, salt, 64);
    return `scrypt:${salt}:${derivedKey.toString('hex')}`;
}

export async function verifyPassword(password, storedHash) {
    const [algorithm, salt, expected] = storedHash.split(':');
    if (algorithm !== 'scrypt' || !salt || !expected) return false;

    const actualKey = await scrypt(password, salt, 64);
    const actual = actualKey.toString('hex');

    return timingSafeEqual(encoder.encode(actual), encoder.encode(expected));
}

export function signJwt(payload, secret, ttlSeconds) {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const now = Math.floor(Date.now() / 1000);
    const body = base64UrlEncode(JSON.stringify({ ...payload, iat: now, exp: now + ttlSeconds }));
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

    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
        throw new Error('Invalid signature');
    }

    const claims = JSON.parse(base64UrlDecode(body));
    if (claims.exp <= Math.floor(Date.now() / 1000)) throw new Error('Expired token');
    return claims;
}

export function generateCsrfToken() {
    return randomBytes(32).toString('hex');
}

export function signCsrfToken(secret, ttlSeconds) {
    const expiresAt = Math.floor(Date.now() / 1000) + ttlSeconds;
    const payload = `${generateCsrfToken()}.${expiresAt}`;
    const signature = createHmac('sha256', secret).update(payload).digest('base64url');
    return `${payload}.${signature}`;
}

export function verifyCsrfToken(token, secret) {
    const [nonce, expiration, signature] = String(token || '').split('.');
    if (!nonce || !expiration || !signature) return false;
    if (Number(expiration) <= Math.floor(Date.now() / 1000)) return false;

    const payload = `${nonce}.${expiration}`;
    const expectedSignature = createHmac('sha256', secret).update(payload).digest('base64url');
    return safeEqual(signature, expectedSignature);
}

export function safeEqual(left, right) {
    const first = Buffer.from(left || '');
    const second = Buffer.from(right || '');
    return first.length === second.length && timingSafeEqual(first, second);
}

export function parseCookies(request) {
    const header = request.headers?.cookie || request.headers?.get?.('cookie') || '';
    if (!header) return {};

    return Object.fromEntries(
        header.split(';').map(part => {
            const index = part.indexOf('=');
            if (index === -1) return null;
            const name = part.slice(0, index).trim();
            const val = part.slice(index + 1).trim();
            return [name, decodeURIComponent(val)];
        }).filter(Boolean)
    );
}

export function serializeCookie(name, value, options = {}) {
    const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'SameSite=Lax'];
    if (options.httpOnly !== false) parts.push('HttpOnly');
    if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
    if (options.secure) parts.push('Secure');
    return parts.join('; ');
}