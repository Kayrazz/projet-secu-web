import { isAbsolute, relative, resolve, sep } from 'node:path';

export function createPathTraversalMiddleware(root, deny) {
    return (request, response, next) => {
        let pathname;
        try {
            pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
        } catch {
            return deny(response, 400, 'Chemin invalide.');
        }

        const filePath = resolve(root, `.${pathname}`);
        const relativePath = relative(root, filePath);
        const outsideRoot = relativePath === '..'
            || relativePath.startsWith(`..${sep}`)
            || isAbsolute(relativePath);

        if (outsideRoot) return deny(response, 403, 'Chemin interdit.');
        request.safePathname = pathname;
        request.safeFilePath = filePath;
        return next();
    };
}
