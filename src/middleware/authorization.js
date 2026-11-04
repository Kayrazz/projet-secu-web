import { findUserById } from '../db.js';
import { getClientIp, logger } from '../logger.js';
import { parseCookies, verifyJwt } from '../security.js';

export function getAuthenticatedUser(request, cookieName, jwtSecret) {
    const token = parseCookies(request)[cookieName];
    if (!token) return null;

    try {
        const claims = verifyJwt(token, jwtSecret);
        return findUserById(Number(claims.sub));
    } catch {
        return null;
    }
}

export function createAuthorizationMiddleware({ getUser, deny }) {
    const requireAuth = async (request, response, next) => {
        const user = getUser(request);
        const route = request.url.split('?')[0];
        if (!user) {
            logger.warn('authorization.unauthenticated', { ip: getClientIp(request), method: request.method, route });
            return deny(response, 401, 'Authentification requise.');
        }

        request.user = user;
        return next();
    };

    const requireRole = role => async (request, response, next) => {
        const route = request.url.split('?')[0];
        await requireAuth(request, response, async () => {
            if (request.user.role !== role) {
                logger.warn('authorization.role_rejected', { ip: getClientIp(request), method: request.method, route, requiredRole: role });
                return deny(response, 403, 'Accès administrateur requis.');
            }
            return next();
        });
    };

    return { requireAuth, requireRole };
}
