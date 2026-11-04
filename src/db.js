import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { hashPassword } from './security.js';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dataDir = join(root, 'data');
const databasePath = join(dataDir, 'shop.db');
mkdirSync(dataDir, { recursive: true });

const database = new DatabaseSync(databasePath);
database.exec(readFileSync(join(dataDir, 'schema.sql'), 'utf8'));
const seed = database.prepare('SELECT id FROM users WHERE email = ?').get('demo@example.com');
if (!seed) {
    database.prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)').run('demo@example.com', await hashPassword('Demo1234!'), 'customer');
}

const adminSeed = database.prepare('SELECT id FROM users WHERE email = ?').get('admin@example.com');
if (!adminSeed) {
    database.prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)').run('admin@example.com', await hashPassword('Admin1234!'), 'admin');
}

export function findUserByEmail(email) {
    return database.prepare('SELECT id, email, password_hash, role FROM users WHERE email = ?').get(email);
}

export function findUserById(id) {
    return database.prepare('SELECT id, email, role FROM users WHERE id = ?').get(id);
}

export function listFigurines() {
    return database.prepare('SELECT id, name, category, image_url, price, created_at FROM figurines ORDER BY id DESC').all();
}

export function findFigurineById(id) {
    return database.prepare('SELECT id, name, category, image_url, price, created_at FROM figurines WHERE id = ?').get(id);
}

export function createFigurine({ name, category, imageUrl, price }) {
    const result = database.prepare('INSERT INTO figurines (name, category, image_url, price) VALUES (?, ?, ?, ?)').run(name, category, imageUrl, price);
    return database.prepare('SELECT id, name, category, image_url, price, created_at FROM figurines WHERE id = ?').get(Number(result.lastInsertRowid));
}
