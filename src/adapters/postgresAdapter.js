/**
 * PostgreSQL adapter (`pg` driver).
 *   npm install pg
 *
 *   const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
 *   const adapter = postgresAdapter({ pool });
 *   await adapter.init(); // creates tables if missing (or run the SQL in a migration)
 *
 * Works with any Postgres-compatible DB (Supabase, Neon, RDS, CockroachDB*).
 */
import { Errors } from '../utils/errors.js';

const UNIQUE_VIOLATION = '23505';
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (id) => UUID_RE.test(String(id));

const COLUMNS = {
  email: 'email',
  passwordHash: 'password_hash',
  name: 'name',
  roles: 'roles',
  emailVerified: 'email_verified',
  createdAt: 'created_at',
  updatedAt: 'updated_at',
};

export const POSTGRES_SCHEMA = `
CREATE TABLE IF NOT EXISTS auth_users (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email          TEXT NOT NULL UNIQUE,
  password_hash  TEXT NOT NULL,
  name           TEXT,
  roles          TEXT[] NOT NULL DEFAULT '{}',
  email_verified BOOLEAN NOT NULL DEFAULT FALSE,
  profile        JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS auth_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id    UUID NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  type       TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  meta       JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS auth_tokens_user_type_idx ON auth_tokens (user_id, type);
`;

export function postgresAdapter({ pool }) {
  const q = (text, params) => pool.query(text, params);

  const mapUser = (row) => {
    if (!row) return null;
    return {
      id: row.id,
      email: row.email,
      passwordHash: row.password_hash,
      name: row.name,
      roles: row.roles,
      emailVerified: row.email_verified,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      ...(row.profile ?? {}), // extra registration fields
    };
  };
  const mapToken = (row) =>
    row ? { tokenHash: row.token_hash, userId: row.user_id, type: row.type, expiresAt: row.expires_at, meta: row.meta } : null;

  // Split known columns from extra fields (stored in `profile` JSONB).
  const split = (fields) => {
    const cols = {}, profile = {};
    for (const [k, v] of Object.entries(fields)) (COLUMNS[k] ? cols : profile)[k] = v;
    return { cols, profile };
  };

  return {
    async init() {
      await q(POSTGRES_SCHEMA);
    },
    async createUser(data) {
      const { cols, profile } = split(data);
      const keys = Object.keys(cols);
      const sql = `INSERT INTO auth_users (${[...keys.map((k) => COLUMNS[k]), 'profile'].join(', ')})
                   VALUES (${[...keys, 'profile'].map((_, i) => `$${i + 1}`).join(', ')}) RETURNING *`;
      try {
        const { rows } = await q(sql, [...keys.map((k) => cols[k]), JSON.stringify(profile)]);
        return mapUser(rows[0]);
      } catch (err) {
        throw err?.code === UNIQUE_VIOLATION ? Errors.emailTaken() : err;
      }
    },
    async findUserByEmail(email) {
      const { rows } = await q('SELECT * FROM auth_users WHERE email = $1', [email]);
      return mapUser(rows[0]);
    },
    async findUserById(id) {
      if (!isUuid(id)) return null;
      const { rows } = await q('SELECT * FROM auth_users WHERE id = $1::uuid', [String(id)]);
      return mapUser(rows[0]);
    },
    async updateUser(id, fields) {
      if (!isUuid(id)) return null;
      const { cols, profile } = split(fields);
      const sets = Object.keys(cols).map((k, i) => `${COLUMNS[k]} = $${i + 2}`);
      const params = [String(id), ...Object.values(cols)];
      if (Object.keys(profile).length) {
        params.push(JSON.stringify(profile));
        sets.push(`profile = profile || $${params.length}::jsonb`);
      }
      if (!sets.length) return this.findUserById(id);
      const { rows } = await q(`UPDATE auth_users SET ${sets.join(', ')} WHERE id = $1::uuid RETURNING *`, params);
      return mapUser(rows[0]);
    },
    async saveToken({ userId, tokenHash, type, expiresAt, meta = {} }) {
      await q('INSERT INTO auth_tokens (token_hash, user_id, type, expires_at, meta) VALUES ($1, $2, $3, $4, $5)', [
        tokenHash, userId, type, expiresAt, JSON.stringify(meta),
      ]);
    },
    async findToken(tokenHash, type) {
      const { rows } = await q('SELECT * FROM auth_tokens WHERE token_hash = $1 AND type = $2', [tokenHash, type]);
      return mapToken(rows[0]);
    },
    async deleteToken(tokenHash) {
      await q('DELETE FROM auth_tokens WHERE token_hash = $1', [tokenHash]);
    },
    async deleteUserTokens(userId, type) {
      if (!isUuid(userId)) return;
      await q('DELETE FROM auth_tokens WHERE user_id = $1::uuid AND type = $2', [String(userId), type]);
    },
  };
}
