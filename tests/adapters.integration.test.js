/**
 * Runs the adapter contract and the main auth flows against real databases. Each
 * suite is skipped unless its connection string is set (CI sets both):
 *   DATABASE_URL=postgres://... MONGO_URL=mongodb://... npm test
 */
import { after, describe, it, test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import express from 'express';
import request from 'supertest';
import { runAdapterContract } from '../src/testing/adapterContract.js';
import { createAuth } from '../src/index.js';
import { postgresAdapter } from '../src/adapters/postgresAdapter.js';
import { mongoAdapter } from '../src/adapters/mongoAdapter.js';

const { DATABASE_URL, MONGO_URL } = process.env;
const bearer = (token) => ['Authorization', `Bearer ${token}`];

function runAuthFlows(name, adapter) {
  function build(options = {}) {
    const sent = {};
    const auth = createAuth({
      adapter,
      jwtSecret: 'test-secret-test-secret-test-secret-1234',
      bcryptRounds: 4,
      rateLimiter: false,
      hooks: { sendPasswordResetEmail: ({ token }) => { sent.reset = token; } },
      ...options,
    });
    const app = express();
    app.use('/auth', auth.router);
    app.get('/private', auth.authenticate, (req, res) => res.json({ id: req.auth.userId }));
    app.use(auth.errorHandler);
    return { app, sent, auth };
  }
  const newCreds = () => ({ email: `${crypto.randomUUID()}@test.dev`, password: 'secret123' });

  describe(`auth flows: ${name}`, () => {
    it('registers, logs in and reaches a protected route', async () => {
      const { app } = build();
      const creds = newCreds();
      await request(app).post('/auth/register').send(creds).expect(201);
      await request(app).post('/auth/register').send(creds).expect(409);
      const { body } = await request(app).post('/auth/login').send(creds).expect(200);
      await request(app).get('/private').set(...bearer(body.accessToken)).expect(200);
    });

    it('lets only one parallel refresh win', async () => {
      const { app } = build();
      const { body } = await request(app).post('/auth/register').send(newCreds());
      const results = await Promise.all(
        Array.from({ length: 5 }, () => request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }))
      );
      assert.equal(results.filter((r) => r.status === 200).length, 1);
    });

    it('ends all sessions when a used refresh token is replayed', async () => {
      const { app } = build({ refreshReuseGraceMs: 0 });
      const { body } = await request(app).post('/auth/register').send(newCreds());
      const { body: next } = await request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }).expect(200);
      await request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }).expect(401);
      await request(app).post('/auth/refresh').send({ refreshToken: next.refreshToken }).expect(401);
      await request(app).get('/private').set(...bearer(next.accessToken)).expect(401);
    });

    it('revokes old access tokens on a password change', async () => {
      const { app } = build();
      const creds = newCreds();
      const { body } = await request(app).post('/auth/register').send(creds);
      const res = await request(app).post('/auth/change-password').set(...bearer(body.accessToken))
        .send({ currentPassword: creds.password, newPassword: 'changed999' }).expect(200);
      await request(app).get('/private').set(...bearer(body.accessToken)).expect(401);
      await request(app).get('/private').set(...bearer(res.body.accessToken)).expect(200);
    });

    it('lets an admin find, promote and disable a user', async () => {
      const { app, auth } = build();
      const adminCreds = newCreds();
      const memberCreds = newCreds();
      await request(app).post('/auth/register').send(adminCreds);
      await auth.service.addRoleByEmail(adminCreds.email, 'admin');
      const { body: admin } = await request(app).post('/auth/login').send(adminCreds);
      const { body: member } = await request(app).post('/auth/register').send(memberCreds);

      const found = await request(app).get('/auth/admin/users').query({ search: memberCreds.email }).set(...bearer(admin.accessToken)).expect(200);
      assert.equal(found.body.total, 1);
      assert.equal(found.body.users[0].id, member.user.id);

      const path = '/auth/admin/users/' + member.user.id;
      const roles = await request(app).put(path + '/roles').set(...bearer(admin.accessToken)).send({ roles: ['user', 'editor'] }).expect(200);
      assert.deepEqual(roles.body.user.roles, ['user', 'editor']);

      await request(app).post(path + '/disable').set(...bearer(admin.accessToken)).expect(200);
      await request(app).post('/auth/login').send(memberCreds).expect(403);
      await request(app).get('/private').set(...bearer(member.accessToken)).expect(401);
      await request(app).post(path + '/enable').set(...bearer(admin.accessToken)).expect(200);
      await request(app).post('/auth/login').send(memberCreds).expect(200);
    });

    it('signs in with a provider, linking and reclaiming accounts', async () => {
      const { app, auth } = build();
      const creds = newCreds();
      const squatter = await request(app).post('/auth/register').send(creds);
      const profile = { provider: 'google', id: crypto.randomUUID(), email: creds.email, emailVerified: true, name: 'Jane' };
      const user = await auth.service.signInWithProvider(profile);
      assert.equal(user.id, squatter.body.user.id);
      assert.equal(user.hasPassword, false);
      await request(app).post('/auth/login').send(creds).expect(401);
      await request(app).get('/private').set(...bearer(squatter.body.accessToken)).expect(401);

      const again = await auth.service.signInWithProvider({ ...profile, email: 'changed-at-provider@example.com' });
      assert.equal(again.id, user.id);
      const code = await auth.service.createLoginCode(user.id);
      const res = await request(app).post('/auth/oauth/exchange').send({ code });
      assert.equal(res.status, 404, 'exchange route needs the oauth option');
      const session = await auth.service.exchangeLoginCode(code);
      await request(app).get('/private').set(...bearer(session.accessToken)).expect(200);
      await assert.rejects(auth.service.exchangeLoginCode(code), { code: 'INVALID_TOKEN' });

      const fresh = await auth.service.signInWithProvider({ provider: 'github', id: crypto.randomUUID(), email: newCreds().email, emailVerified: true });
      assert.equal(fresh.emailVerified, true);
      await request(app).delete('/auth/me').set(...bearer((await auth.service.exchangeLoginCode(await auth.service.createLoginCode(fresh.id))).accessToken))
        .send({ confirmEmail: fresh.email }).expect(204);
    });

    it('resets a password and revokes old access tokens', async () => {
      const { app, sent } = build();
      const creds = newCreds();
      const { body } = await request(app).post('/auth/register').send(creds);
      await request(app).post('/auth/forgot-password').send({ email: creds.email }).expect(200);
      for (let i = 0; i < 100 && !sent.reset; i++) await new Promise((resolve) => setTimeout(resolve, 10));
      await request(app).post('/auth/reset-password').send({ token: sent.reset, newPassword: 'changed999' }).expect(204);
      await request(app).get('/private').set(...bearer(body.accessToken)).expect(401);
      await request(app).post('/auth/login').send({ email: creds.email, password: 'changed999' }).expect(200);
    });
  });
}

if (DATABASE_URL) {
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({ connectionString: DATABASE_URL });
  const adapter = postgresAdapter({ pool });
  await adapter.init();
  runAdapterContract('postgres', () => adapter);
  runAuthFlows('postgres', adapter);
  after(() => pool.end());
} else {
  test('adapter contract: postgres', { skip: 'DATABASE_URL not set' }, () => {});
}

if (MONGO_URL) {
  const { MongoClient, ObjectId } = await import('mongodb');
  const client = await new MongoClient(MONGO_URL).connect();
  const adapter = mongoAdapter({ db: client.db('auth_kit_test'), ObjectId });
  await adapter.init();
  runAdapterContract('mongo', () => adapter);
  runAuthFlows('mongo', adapter);
  after(() => client.close());
} else {
  test('adapter contract: mongo', { skip: 'MONGO_URL not set' }, () => {});
}
