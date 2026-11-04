import { findUserById } from '../db.js';
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
        if (!user) return deny(response, 401, 'Authentification requise.');

        request.user = user;
        return next();
    };

    const requireRole = role => async (request, response, next) => {
        await requireAuth(request, response, async () => {
            if (request.user.role !== role) return deny(response, 403, 'Accès administrateur requis.');
            return next();
        });
    };

    return { requireAuth, requireRole };
}
