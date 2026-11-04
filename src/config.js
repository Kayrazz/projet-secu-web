import { randomBytes } from 'node:crypto';

const port = Number(process.env.PORT || 3000);
const jwtSecret = process.env.JWT_SECRET || randomBytes(32).toString('hex');

export const config = {
    port,
    jwtSecret,
    nodeEnv: process.env.NODE_ENV || 'development',
    cookieName: 'shop_session',
    tokenTtlSeconds: 60 * 60,
    apiRateLimit: 100,
    apiRateLimitWindowMs: 60_000,
    loginRateLimit: 5,
    loginRateLimitWindowMs: 60_000,
    enableBrokenAuthLab: process.env.ENABLE_BROKEN_AUTH_LAB === 'true'
};
