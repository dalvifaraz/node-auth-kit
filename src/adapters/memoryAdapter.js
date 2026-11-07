import crypto from 'node:crypto';
import { Errors } from '../utils/errors.js';

/** In-memory adapter — for tests, demos and prototyping. Data is lost on restart. */
export function memoryAdapter() {
  const users = new Map();
  const tokens = new Map();
  const identities = new Map(); // "provider:providerUserId" -> userId
  const clone = (v) => (v ? structuredClone(v) : null);

  return {
    async createUser(data) {
      for (const u of users.values()) if (u.email === data.email) throw Errors.emailTaken();
      const user = { id: crypto.randomUUID(), ...data };
      users.set(user.id, user);
      return clone(user);
    },
    async findUserByEmail(email) {
      for (const u of users.values()) if (u.email === email) return clone(u);
      return null;
    },
    async findUserById(id) {
      return clone(users.get(String(id)));
    },
    async updateUser(id, fields) {
      const u = users.get(String(id));
      if (!u) return null;
      if (fields.email && fields.email !== u.email) {
        for (const other of users.values()) if (other.email === fields.email) throw Errors.emailTaken();
      }
      Object.assign(u, fields);
      return clone(u);
    },
    async deleteUser(id) {
      users.delete(String(id));
      for (const [k, t] of tokens) if (t.userId === String(id)) tokens.delete(k);
      for (const [k, userId] of identities) if (userId === String(id)) identities.delete(k);
    },
    async findUserIdByIdentity(provider, providerUserId) {
      return identities.get(`${provider}:${providerUserId}`) ?? null;
    },
    async linkIdentity({ userId, provider, providerUserId }) {
      const key = `${provider}:${providerUserId}`;
      if (identities.has(key)) throw Errors.identityTaken();
      identities.set(key, String(userId));
    },
    async listUsers({ limit, offset, search }) {
      const matches = [...users.values()]
        .filter((u) => !search || u.email.includes(search))
        .sort((a, b) => b.createdAt - a.createdAt);
      return { users: matches.slice(offset, offset + limit).map(clone), total: matches.length };
    },
    async saveToken(record) {
      tokens.set(record.tokenHash, { ...record });
    },
    async findToken(tokenHash, type) {
      const t = tokens.get(tokenHash);
      return t && t.type === type ? clone(t) : null;
    },
    async consumeToken(tokenHash, type) {
      const t = tokens.get(tokenHash);
      if (!t || t.type !== type) return null;
      tokens.delete(tokenHash);
      return clone(t);
    },
    async deleteToken(tokenHash) {
      tokens.delete(tokenHash);
    },
    async deleteExpiredTokens() {
      const now = Date.now();
      for (const [k, t] of tokens) if (new Date(t.expiresAt).getTime() < now) tokens.delete(k);
    },
    async deleteUserTokens(userId, type) {
      for (const [k, t] of tokens) if (t.userId === String(userId) && t.type === type) tokens.delete(k);
    },
  };
}
