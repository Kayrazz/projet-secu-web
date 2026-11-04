import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const sensitiveKey = /password|token|secret|cookie|authorization|body|email/i;
const logFile = join(dirname(fileURLToPath(import.meta.url)), '..', 'logs', 'app.log');
mkdirSync(dirname(logFile), { recursive: true });

function sanitizeDetails(details) {
    return Object.fromEntries(Object.entries(details).filter(([key]) => !sensitiveKey.test(key)).map(([key, value]) => {
        if (typeof value === 'string') return [key, value.slice(0, 160)];
        return [key, value];
    }));
}

export function getClientIp(request) {
    const address = request.socket?.remoteAddress || 'unknown';
    return address.startsWith('::ffff:') ? address.slice(7) : address;
}

function write(level, event, details = {}) {
    const entry = {
        timestamp: new Date().toISOString(),
        level,
        event,
        ...sanitizeDetails(details)
    };
    const line = JSON.stringify(entry);
    console[level === 'error' ? 'error' : 'log'](line);

    try {
        appendFileSync(logFile, `${line}\n`, 'utf8');
    } catch {
        // Les erreurs d'écriture des logs ne doivent pas arrêter le serveur.
    }
}

export const logger = {
    info(event, details) {
        write('info', event, details);
    },
    warn(event, details) {
        write('warn', event, details);
    },
    error(event, details) {
        write('error', event, details);
    }
};
