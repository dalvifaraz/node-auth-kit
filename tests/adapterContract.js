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

    it('rejects a duplicate email with EMAIL_TAKEN', async () => {
      const a = await makeAdapter();
      const u = await newUser(a);
      await assert.rejects(newUser(a, { email: u.email }), { code: 'EMAIL_TAKEN' });
    });

    it('allows only one of several concurrent creates for an email', async () => {
      const a = await makeAdapter();
      const email = `${uid()}@test.dev`;
      const results = await Promise.allSettled([1, 2, 3].map(() => newUser(a, { email })));
      assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
    });

    it('stores extra fields', async () => {
      const a = await makeAdapter();
      const u = await newUser(a, { phone: '123' });
      assert.equal((await a.findUserById(u.id)).phone, '123');
    });

    it('updates users', async () => {
      const a = await makeAdapter();
      const u = await newUser(a);
      const updated = await a.updateUser(u.id, { emailVerified: true, value: 'x' });
      assert.equal(updated.emailVerified, true);
      assert.equal(updated.email, u.email);
      assert.equal((await a.findUserById(u.id)).emailVerified, true);
    });

    it('stores tokenVersion and disabled', async () => {
      const a = await makeAdapter();
      const u = await newUser(a, { tokenVersion: 0, disabled: false });
      await a.updateUser(u.id, { tokenVersion: 3, disabled: true });
      const found = await a.findUserById(u.id);
      assert.equal(found.tokenVersion, 3);
      assert.equal(found.disabled, true);
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

    it('deletes only expired tokens', async () => {
      const a = await makeAdapter();
      const u = await newUser(a);
      const expired = tokenFor(u, { expiresAt: new Date(Date.now() - 60000) });
      const live = tokenFor(u);
      await a.saveToken(expired);
      await a.saveToken(live);
      await a.deleteExpiredTokens();
      assert.equal(await a.findToken(expired.tokenHash, 'refresh'), null);
      assert.ok(await a.findToken(live.tokenHash, 'refresh'));
    });

    it('consumes a token once, and only for its own type', async () => {
      const a = await makeAdapter();
      const rec = tokenFor(await newUser(a));
      await a.saveToken(rec);
      assert.equal(await a.consumeToken(rec.tokenHash, 'password_reset'), null);
      assert.equal((await a.consumeToken(rec.tokenHash, 'refresh')).userId, rec.userId);
      assert.equal(await a.consumeToken(rec.tokenHash, 'refresh'), null);
    });

    it('lets exactly one concurrent consume win', async () => {
      const a = await makeAdapter();
      const rec = tokenFor(await newUser(a));
      await a.saveToken(rec);
      const results = await Promise.all(Array.from({ length: 5 }, () => a.consumeToken(rec.tokenHash, 'refresh')));
      assert.equal(results.filter(Boolean).length, 1);
    });
  });
}
