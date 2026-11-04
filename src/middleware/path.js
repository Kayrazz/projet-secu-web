import { isAbsolute, relative, resolve, sep } from 'node:path';
import { getClientIp, logger } from '../logger.js';

export function createPathTraversalMiddleware(root, deny) {
    return (request, response, next) => {
        let pathname;
        try {
            pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
        } catch {
            logger.warn('path.invalid_encoding', { ip: getClientIp(request) });
            return deny(response, 400, 'Chemin invalide.');
        }

        const filePath = resolve(root, `.${pathname}`);
        const relativePath = relative(root, filePath);
        const outsideRoot = relativePath === '..'
            || relativePath.startsWith(`..${sep}`)
            || isAbsolute(relativePath);

        if (outsideRoot) {
            logger.warn('path.traversal_rejected', { ip: getClientIp(request) });
            return deny(response, 403, 'Chemin interdit.');
        }
        request.safePathname = pathname;
        request.safeFilePath = filePath;
        return next();
    };
}
