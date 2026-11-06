/**
 * Reusable contract tests. Run them against ANY adapter to prove it works with the core:
 *   import { runAdapterContract } from './adapterContract.js';
 *   runAdapterContract('postgres', () => postgresAdapter({ pool }));
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const uid = () => crypto.randomUUID();
const newUser = (a, fields = {}) =>
  a.createUser({ email: `${uid()}@test.dev`, passwordHash: 'x', name: 'A', roles: ['user'], emailVerified: false, ...fields });
const tokenFor = (user, fields = {}) => ({
  userId: String(user.id), tokenHash: uid(), type: 'refresh', expiresAt: new Date(Date.now() + 1e5), meta: {}, ...fields,
});

export function runAdapterContract(name, makeAdapter) {
  describe(`adapter contract: ${name}`, () => {
    it('creates and finds users', async () => {
      const a = await makeAdapter();
      const u = await newUser(a);
      assert.ok(u.id);
      assert.equal((await a.findUserByEmail(u.email)).id, String(u.id));
      assert.equal((await a.findUserById(u.id)).email, u.email);
      assert.equal(await a.findUserByEmail('nobody@test.dev'), null);
    });

    it('returns null for an unknown or malformed user id', async () => {
      const a = await makeAdapter();
      assert.equal(await a.findUserById('not-a-valid-id'), null);
    });

    it('updates users', async () => {
      const a = await makeAdapter();
      const u = await newUser(a);
      await a.updateUser(u.id, { emailVerified: true });
      assert.equal((await a.findUserById(u.id)).emailVerified, true);
    });

    it('stores, finds and deletes tokens', async () => {
      const a = await makeAdapter();
      const u = await newUser(a);
      const rec = tokenFor(u);
      await a.saveToken(rec);
      assert.equal((await a.findToken(rec.tokenHash, 'refresh')).userId, String(u.id));
      assert.equal(await a.findToken(rec.tokenHash, 'password_reset'), null);
      await a.deleteToken(rec.tokenHash);
      assert.equal(await a.findToken(rec.tokenHash, 'refresh'), null);

      const [t1, t2] = [tokenFor(u), tokenFor(u)];
      await a.saveToken(t1);
      await a.saveToken(t2);
      await a.deleteUserTokens(u.id, 'refresh');
      assert.equal(await a.findToken(t1.tokenHash, 'refresh'), null);
      assert.equal(await a.findToken(t2.tokenHash, 'refresh'), null);
    });
  });
}
