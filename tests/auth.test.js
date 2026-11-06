import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import request from 'supertest';
import { createAuth, memoryAdapter } from '../src/index.js';
import { runAdapterContract } from './adapterContract.js';

runAdapterContract('memory', () => memoryAdapter());

function buildApp(overrides = {}) {
  const sent = {};
  const auth = createAuth({
    adapter: memoryAdapter(),
    jwtSecret: 'test-secret-test-secret-test-secret-1234',
    bcryptRounds: 4, // fast tests
    rateLimiter: false,
    hooks: {
      sendPasswordResetEmail: ({ user, token }) => { sent.reset = { email: user.email, token }; },
      sendVerificationEmail: ({ user, token }) => { sent.verify = { email: user.email, token }; },
    },
    ...overrides,
  });
  const app = express();
  app.use('/auth', auth.router);
  app.get('/private', auth.authenticate, (req, res) => res.json({ userId: req.auth.userId }));
  app.get('/admin', auth.authenticate, auth.requireRoles('admin'), (_req, res) => res.json({ ok: true }));
  app.use(auth.errorHandler);
  return { app, sent };
}

const creds = { email: 'Jane@Example.com', password: 'secret123' };

describe('auth flow', () => {
  let app, sent;
  before(() => ({ app, sent } = buildApp()));

  it('registers a user and hides the password hash', async () => {
    const res = await request(app).post('/auth/register').send({ ...creds, name: 'Jane' }).expect(201);
    assert.equal(res.body.user.email, 'jane@example.com');
    assert.equal(res.body.user.passwordHash, undefined);
    assert.ok(res.body.accessToken && res.body.refreshToken);
  });

  it('rejects duplicate email and weak passwords', async () => {
    await request(app).post('/auth/register').send(creds).expect(409);
    const weak = await request(app).post('/auth/register').send({ email: 'x@y.com', password: 'short' }).expect(400);
    assert.equal(weak.body.error.code, 'VALIDATION_ERROR');
  });

  it('logs in, rejects bad password with a generic error', async () => {
    await request(app).post('/auth/login').send(creds).expect(200);
    const bad = await request(app).post('/auth/login').send({ ...creds, password: 'wrong1234' }).expect(401);
    const none = await request(app).post('/auth/login').send({ email: 'no@one.com', password: 'wrong1234' }).expect(401);
    assert.equal(bad.body.error.message, none.body.error.message);
  });

  it('protects routes with the access token', async () => {
    await request(app).get('/private').expect(401);
    await request(app).get('/private').set('Authorization', 'Bearer garbage').expect(401);
    const { body } = await request(app).post('/auth/login').send(creds);
    await request(app).get('/private').set('Authorization', `Bearer ${body.accessToken}`).expect(200);
    const me = await request(app).get('/auth/me').set('Authorization', `Bearer ${body.accessToken}`).expect(200);
    assert.equal(me.body.user.email, 'jane@example.com');
  });

  it('enforces roles', async () => {
    const { body } = await request(app).post('/auth/login').send(creds);
    await request(app).get('/admin').set('Authorization', `Bearer ${body.accessToken}`).expect(403);
  });

  it('rotates refresh tokens (old one cannot be reused)', async () => {
    const { body } = await request(app).post('/auth/login').send(creds);
    const r1 = await request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }).expect(200);
    assert.notEqual(r1.body.refreshToken, body.refreshToken);
    await request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }).expect(401);
  });

  it('logout revokes the refresh token', async () => {
    const { body } = await request(app).post('/auth/login').send(creds);
    await request(app).post('/auth/logout').send({ refreshToken: body.refreshToken }).expect(204);
    await request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }).expect(401);
  });

  it('forgot/reset password flow', async () => {
    const res = await request(app).post('/auth/forgot-password').send({ email: creds.email }).expect(200);
    await request(app).post('/auth/forgot-password').send({ email: 'ghost@x.com' }).expect(200); // same response
    assert.ok(res.body.message);
    assert.ok(sent.reset.token);
    await request(app).post('/auth/reset-password').send({ token: sent.reset.token, newPassword: 'newpass456' }).expect(204);
    await request(app).post('/auth/reset-password').send({ token: sent.reset.token, newPassword: 'again789x' }).expect(401);
    await request(app).post('/auth/login').send(creds).expect(401);
    await request(app).post('/auth/login').send({ ...creds, password: 'newpass456' }).expect(200);
    creds.password = 'newpass456';
  });

  it('change password signs out other sessions', async () => {
    const { body } = await request(app).post('/auth/login').send(creds);
    await request(app)
      .post('/auth/change-password')
      .set('Authorization', `Bearer ${body.accessToken}`)
      .send({ currentPassword: creds.password, newPassword: 'changed999' })
      .expect(204);
    await request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }).expect(401);
  });
});

describe('concurrency', () => {
  it('returns 409 to the losers of a concurrent register', async () => {
    const { app } = buildApp();
    const results = await Promise.all([1, 2, 3].map(() => request(app).post('/auth/register').send(creds)));
    assert.deepEqual(results.map((r) => r.status).sort(), [201, 409, 409]);
  });
});

describe('email verification', () => {
  it('blocks login until verified when required', async () => {
    const { app, sent } = buildApp({ emailVerification: true, requireVerifiedEmail: true });
    await request(app).post('/auth/register').send(creds).expect(201);
    await request(app).post('/auth/login').send({ ...creds }).expect(403);
    await request(app).post('/auth/verify-email').send({ token: sent.verify.token }).expect(204);
    await request(app).post('/auth/login').send({ ...creds }).expect(200);
  });
});

describe('configuration', () => {
  it('fails fast on a bad adapter or weak secret', () => {
    assert.throws(() => createAuth({ adapter: {}, jwtSecret: 'x'.repeat(32) }), /missing methods/);
    assert.throws(() => createAuth({ adapter: memoryAdapter(), jwtSecret: 'short' }), /at least 32/);
  });
});
