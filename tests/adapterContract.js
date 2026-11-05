/**
 * Reusable contract tests. Run them against ANY adapter to prove it works with the core:
 *   import { runAdapterContract } from './adapterContract.js';
 *   runAdapterContract('postgres', () => postgresAdapter({ pool }));
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

export function runAdapterContract(name, makeAdapter) {
  describe(`adapter contract: ${name}`, () => {
    it('creates and finds users', async () => {
      const a = await makeAdapter();
      const email = `u${Date.now()}@test.dev`;
      const u = await a.createUser({ email, passwordHash: 'x', name: 'A', roles: ['user'], emailVerified: false });
      assert.ok(u.id);
      assert.equal((await a.findUserByEmail(email)).id, String(u.id));
      assert.equal((await a.findUserById(u.id)).email, email);
      assert.equal(await a.findUserByEmail('nobody@test.dev'), null);
    });

    it('updates users', async () => {
      const a = await makeAdapter();
      const u = await a.createUser({ email: `v${Date.now()}@test.dev`, passwordHash: 'x', roles: [], emailVerified: false });
      await a.updateUser(u.id, { emailVerified: true });
      assert.equal((await a.findUserById(u.id)).emailVerified, true);
    });

    it('stores, finds and deletes tokens', async () => {
      const a = await makeAdapter();
      const u = await a.createUser({ email: `t${Date.now()}@test.dev`, passwordHash: 'x', roles: [], emailVerified: false });
      const rec = { userId: String(u.id), tokenHash: `h${Date.now()}`, type: 'refresh', expiresAt: new Date(Date.now() + 1e5), meta: {} };
      await a.saveToken(rec);
      assert.equal((await a.findToken(rec.tokenHash, 'refresh')).userId, String(u.id));
      assert.equal(await a.findToken(rec.tokenHash, 'password_reset'), null);
      await a.deleteToken(rec.tokenHash);
      assert.equal(await a.findToken(rec.tokenHash, 'refresh'), null);

      await a.saveToken({ ...rec, tokenHash: 'h1' });
      await a.saveToken({ ...rec, tokenHash: 'h2' });
      await a.deleteUserTokens(u.id, 'refresh');
      assert.equal(await a.findToken('h1', 'refresh'), null);
      assert.equal(await a.findToken('h2', 'refresh'), null);
    });
  });
}
