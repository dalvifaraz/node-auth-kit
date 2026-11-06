import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';

/** bcrypt ignores everything after this many bytes. */
export const MAX_PASSWORD_BYTES = 72;

export const hashPassword = (plain, rounds = 12) => bcrypt.hash(plain, rounds);
export const verifyPassword = (plain, hash) => bcrypt.compare(plain, hash);

/** Random opaque token (for refresh / reset / verify tokens). */
export const randomToken = (bytes = 48) => crypto.randomBytes(bytes).toString('base64url');

/** We never store raw opaque tokens in the DB — only their SHA-256 hash. */
export const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
