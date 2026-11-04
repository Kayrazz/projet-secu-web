import { randomBytes } from 'node:crypto';

const port = Number(process.env.PORT || 3000);
const jwtSecret = process.env.JWT_SECRET || randomBytes(32).toString('hex');
const maxUploadBytes = Number(process.env.MAX_UPLOAD_BYTES || 5 * 1024 * 1024);

export const config = {
    port,
    jwtSecret,
    uploadDir: process.env.UPLOAD_DIR || '/public/uploads',
    logsDir: process.env.LOGS_DIR || '/logs',
    nodeEnv: process.env.NODE_ENV || 'development',
    cookieName: 'shop_session',
    tokenTtlSeconds: 60 * 60,
    apiRateLimit: 100,
    apiRateLimitWindowMs: 60_000,
    loginRateLimit: 5,
    loginRateLimitWindowMs: 60_000,
    maxUploadBytes: Number.isSafeInteger(maxUploadBytes) && maxUploadBytes > 0
        ? maxUploadBytes
        : 5 * 1024 * 1024,
    enableBrokenAuthLab: process.env.ENABLE_BROKEN_AUTH_LAB === 'true'
};
