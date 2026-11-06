import crypto from 'node:crypto';
import { Errors } from '../utils/errors.js';

/** In-memory adapter — for tests, demos and prototyping. Data is lost on restart. */
export function memoryAdapter() {
  const users = new Map();
  const tokens = new Map();
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
      Object.assign(u, fields);
      return clone(u);
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
