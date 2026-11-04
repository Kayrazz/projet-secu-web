import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

const allowedMimeTypes = new Map([
    ['image/jpeg', { extension: 'jpg', matches: buffer => buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff }],
    ['image/png', { extension: 'png', matches: buffer => buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) }],
    ['image/gif', { extension: 'gif', matches: buffer => buffer.subarray(0, 6).toString('ascii') === 'GIF89a' || buffer.subarray(0, 6).toString('ascii') === 'GIF87a' }],
    ['image/webp', { extension: 'webp', matches: buffer => buffer.subarray(0, 4).toString('ascii') === 'RIFF' && buffer.subarray(8, 12).toString('ascii') === 'WEBP' }]
]);

async function readRequestBody(request, maxUploadBytes) {
    const chunks = [];
    let totalSize = 0;

    for await (const chunk of request) {
        totalSize += chunk.length;
        if (totalSize > maxUploadBytes + 100_000) throw new Error('Fichier trop volumineux.');
        chunks.push(chunk);
    }

    return Buffer.concat(chunks);
}

function parseHeaders(headerBlock) {
    return Object.fromEntries(headerBlock.split('\r\n').map(line => {
        const separator = line.indexOf(':');
        return [line.slice(0, separator).toLowerCase(), line.slice(separator + 1).trim()];
    }));
}

function parseMultipartFile(body, boundary) {
    const delimiter = Buffer.from(`--${boundary}`);
    let cursor = body.indexOf(delimiter);

    while (cursor !== -1) {
        const contentStart = body.indexOf(Buffer.from('\r\n\r\n'), cursor);
        if (contentStart === -1) break;
        const dataStart = contentStart + 4;
        const nextBoundary = body.indexOf(delimiter, dataStart);
        if (nextBoundary === -1) break;

        const headerBlock = body.subarray(cursor + delimiter.length + 2, contentStart).toString('utf8');
        const headers = parseHeaders(headerBlock);
        if (headers['content-disposition']?.includes('filename=')) {
            return { mimeType: headers['content-type'], data: body.subarray(dataStart, nextBoundary - 2) };
        }
        cursor = nextBoundary;
    }

    return null;
}

export async function saveUploadedImage(request, uploadDirectory, maxUploadBytes) {
    const contentType = request.headers['content-type'] || '';
    const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
    if (!contentType.toLowerCase().startsWith('multipart/form-data') || !boundaryMatch) throw new Error('Format multipart requis.');

    const file = parseMultipartFile(await readRequestBody(request), boundaryMatch[1] || boundaryMatch[2]);
    const mime = allowedMimeTypes.get(file?.mimeType?.toLowerCase());
    if (!file || !mime || file.data.length === 0 || file.data.length > maxUploadBytes || !mime.matches(file.data)) {
        throw new Error('Type MIME ou contenu de fichier non autorisé.');
    }

    await mkdir(uploadDirectory, { recursive: true });
    const filename = `${randomUUID()}.${mime.extension}`;
    await writeFile(join(uploadDirectory, filename), file.data, { flag: 'wx' });
    return { imageUrl: `/uploads/${filename}`, size: file.data.length, mimeType: file.mimeType };
}
