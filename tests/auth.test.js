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
  return { app, sent, auth };
}

const bearer = (token) => ['Authorization', 'Bearer ' + token];

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
      .expect(200);
    await request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }).expect(401);
  });
});

describe('concurrency', () => {
  it('lets only one concurrent refresh win', async () => {
    const { app } = buildApp();
    const { body } = await request(app).post('/auth/register').send(creds);
    const results = await Promise.all(
      Array.from({ length: 5 }, () => request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }))
    );
    assert.equal(results.filter((r) => r.status === 200).length, 1);
  });

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

describe('required email verification', () => {
  it('gives an unverified user no tokens at register', async () => {
    const { app } = buildApp({ requireVerifiedEmail: true });
    const res = await request(app).post('/auth/register').send(creds).expect(201);
    assert.equal(res.body.user.email, 'jane@example.com');
    assert.equal(res.body.accessToken, undefined);
    assert.equal(res.body.refreshToken, undefined);
  });

  it('blocks refresh for an unverified user', async () => {
    const { app, auth } = buildApp({ requireVerifiedEmail: true });
    const { body } = await request(app).post('/auth/register').send(creds);
    const { refreshToken } = await auth.tokens.issueTokenPair(body.user);
    await request(app).post('/auth/refresh').send({ refreshToken }).expect(403);
  });

  it('sends the verification email without emailVerification being set', async () => {
    const { app, sent } = buildApp({ requireVerifiedEmail: true });
    await request(app).post('/auth/register').send(creds);
    assert.ok(sent.verify.token);
  });

  it('rejects contradictory options at startup', () => {
    assert.throws(() => buildApp({ requireVerifiedEmail: true, emailVerification: false }), /requireVerifiedEmail/);
  });
});

describe('password length', () => {
  const email = 'long@example.com';
  const max = 'a1'.repeat(36); // exactly 72 bytes

  it('rejects a password over 72 bytes, even with a custom policy', async () => {
    const { app } = buildApp({ passwordPolicy: () => null });
    await request(app).post('/auth/register').send({ email, password: max + 'x' }).expect(400);
  });

  it('does not accept a longer password that shares the first 72 bytes', async () => {
    const { app } = buildApp();
    await request(app).post('/auth/register').send({ email, password: max }).expect(201);
    await request(app).post('/auth/login').send({ email, password: max + 'x' }).expect(401);
    await request(app).post('/auth/login').send({ email, password: max }).expect(200);
  });
});

describe('public user fields', () => {
  it('returns allowlisted fields and hides everything else', async () => {
    const adapter = memoryAdapter();
    const { app } = buildApp({ adapter, allowedRegisterFields: ['phone'], publicUserFields: ['plan', 'passwordHash'] });
    const { body } = await request(app).post('/auth/register').send({ ...creds, phone: '123' });
    await adapter.updateUser(body.user.id, { totpSecret: 'SECRET', plan: 'pro' });
    const { body: me } = await request(app).get('/auth/me').set(...bearer(body.accessToken));
    assert.equal(me.user.phone, '123');
    assert.equal(me.user.plan, 'pro');
    assert.equal(me.user.totpSecret, undefined);
    assert.equal(me.user.passwordHash, undefined);
  });
});

describe('rate limiting', () => {
  const bad = { email: creds.email, password: 'wrong1234' };
  const limited = (max) => buildApp({ rateLimiter: undefined, rateLimit: { max, windowMs: 60000 } }).app;

  it('counts path variants of a route together', async () => {
    const app = limited(2);
    await request(app).post('/auth/login').send(bad).expect(401);
    await request(app).post('/auth/login').send(bad).expect(401);
    for (const path of ['/auth/login', '/auth/login/', '/auth/LOGIN', '/AUTH/Login']) {
      await request(app).post(path).send(bad).expect(429);
    }
  });

  it('limits change-password', async () => {
    const app = limited(1);
    const { body } = await request(app).post('/auth/register').send(creds);
    const attempt = () => request(app).post('/auth/change-password').set(...bearer(body.accessToken))
      .send({ currentPassword: 'wrong1234', newPassword: 'changed999' });
    await attempt().expect(401);
    await attempt().expect(429);
  });

  it('can be turned off with rateLimit: false', async () => {
    const { app } = buildApp({ rateLimiter: undefined, rateLimit: false });
    for (let i = 0; i < 12; i++) await request(app).post('/auth/login').send(bad).expect(401);
  });
});

describe('access token revocation', () => {
  async function session(overrides) {
    const adapter = memoryAdapter();
    const ctx = buildApp({ adapter, ...overrides });
    const { body } = await request(ctx.app).post('/auth/register').send(creds);
    return { ...ctx, adapter, body };
  }

  it('rejects old access tokens after a password change and keeps the caller signed in', async () => {
    const { app, body } = await session();
    const res = await request(app).post('/auth/change-password').set(...bearer(body.accessToken))
      .send({ currentPassword: creds.password, newPassword: 'changed999' }).expect(200);
    await request(app).get('/private').set(...bearer(body.accessToken)).expect(401);
    await request(app).get('/private').set(...bearer(res.body.accessToken)).expect(200);
    await request(app).post('/auth/refresh').send({ refreshToken: res.body.refreshToken }).expect(200);
    assert.equal(res.body.user.tokenVersion, undefined);
  });

  it('rejects old access tokens after logout-all', async () => {
    const { app, body } = await session();
    await request(app).post('/auth/logout-all').set(...bearer(body.accessToken)).expect(204);
    await request(app).get('/private').set(...bearer(body.accessToken)).expect(401);
  });

  it('rejects old access tokens after a password reset', async () => {
    const { app, sent, body } = await session();
    await request(app).post('/auth/forgot-password').send({ email: creds.email });
    await request(app).post('/auth/reset-password').send({ token: sent.reset.token, newPassword: 'changed999' }).expect(204);
    await request(app).get('/private').set(...bearer(body.accessToken)).expect(401);
  });

  it('applies role changes to existing access tokens', async () => {
    const { app, adapter, body } = await session();
    await request(app).get('/admin').set(...bearer(body.accessToken)).expect(403);
    await adapter.updateUser(body.user.id, { roles: ['admin'] });
    await request(app).get('/admin').set(...bearer(body.accessToken)).expect(200);
  });

  it('rejects the token of a user who no longer exists', async () => {
    const { app, auth } = buildApp();
    const token = auth.tokens.signAccessToken({ id: 'gone', email: 'x@y.co' });
    await request(app).get('/private').set(...bearer(token)).expect(401);
  });

  it('skips the database check with checkTokenVersion: false', async () => {
    const { app, body } = await session({ checkTokenVersion: false });
    await request(app).post('/auth/logout-all').set(...bearer(body.accessToken)).expect(204);
    await request(app).get('/private').set(...bearer(body.accessToken)).expect(200);
  });
});

describe('refresh token reuse', () => {
  it('ends all sessions when a used token is replayed', async () => {
    const { app } = buildApp({ refreshReuseGraceMs: 0 });
    const { body } = await request(app).post('/auth/register').send(creds);
    const { body: next } = await request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }).expect(200);
    await request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }).expect(401);
    await request(app).post('/auth/refresh').send({ refreshToken: next.refreshToken }).expect(401);
    await request(app).get('/private').set(...bearer(next.accessToken)).expect(401);
  });

  it('leaves sessions alone for a replay within the grace period', async () => {
    const { app } = buildApp();
    const { body } = await request(app).post('/auth/register').send(creds);
    const { body: next } = await request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }).expect(200);
    await request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }).expect(401);
    await request(app).post('/auth/refresh').send({ refreshToken: next.refreshToken }).expect(200);
  });

  it('does not treat a logged-out token as stolen', async () => {
    const { app } = buildApp({ refreshReuseGraceMs: 0 });
    await request(app).post('/auth/register').send(creds);
    const { body: a } = await request(app).post('/auth/login').send(creds);
    const { body: b } = await request(app).post('/auth/login').send(creds);
    await request(app).post('/auth/logout').send({ refreshToken: a.refreshToken }).expect(204);
    await request(app).post('/auth/refresh').send({ refreshToken: a.refreshToken }).expect(401);
    await request(app).post('/auth/refresh').send({ refreshToken: b.refreshToken }).expect(200);
  });
});

describe('forgot-password privacy', () => {
  it('does not wait for the email hook', async () => {
    const hooks = { sendPasswordResetEmail: () => new Promise((resolve) => setTimeout(resolve, 300)) };
    const { app } = buildApp({ hooks });
    await request(app).post('/auth/register').send(creds);
    const start = performance.now();
    await request(app).post('/auth/forgot-password').send({ email: creds.email }).expect(200);
    assert.ok(performance.now() - start < 200);
  });

  it('responds the same when the email hook fails', async () => {
    const logged = [];
    const original = console.error;
    console.error = (...args) => logged.push(args);
    try {
      const hooks = { sendPasswordResetEmail: async () => { throw new Error('smtp down'); } };
      const { app } = buildApp({ hooks });
      await request(app).post('/auth/register').send(creds);
      const known = await request(app).post('/auth/forgot-password').send({ email: creds.email }).expect(200);
      const unknown = await request(app).post('/auth/forgot-password').send({ email: 'ghost@x.com' }).expect(200);
      assert.deepEqual(known.body, unknown.body);
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(logged.length, 1);
    } finally {
      console.error = original;
    }
  });
});

describe('invalid input', () => {
  it('ignores a non-string refresh token on logout', async () => {
    const { app } = buildApp();
    await request(app).post('/auth/logout').send({ refreshToken: 123 }).expect(204);
  });

  it('treats a non-string current password as wrong', async () => {
    const { app } = buildApp();
    const { body } = await request(app).post('/auth/register').send(creds);
    await request(app).post('/auth/change-password').set(...bearer(body.accessToken))
      .send({ currentPassword: 123, newPassword: 'changed999' }).expect(401);
  });

  it('rejects a name that is not short text', async () => {
    const { app } = buildApp();
    await request(app).post('/auth/register').send({ ...creds, name: { $gt: '' } }).expect(400);
    await request(app).post('/auth/register').send({ ...creds, name: 'x'.repeat(101) }).expect(400);
  });

  it('rejects an over-long email', async () => {
    const { app } = buildApp();
    await request(app).post('/auth/login').send({ email: 'a'.repeat(250) + '@b.co', password: 'x' }).expect(400);
  });

  it('reports bad bodies as client errors', async () => {
    const { app } = buildApp();
    const big = await request(app).post('/auth/login').send({ email: 'x'.repeat(20000) }).expect(413);
    assert.equal(big.body.error.code, 'PAYLOAD_TOO_LARGE');
    const bad = await request(app).post('/auth/login').set('Content-Type', 'application/json').send('{oops').expect(400);
    assert.equal(bad.body.error.code, 'BAD_JSON');
  });

  it('accepts the bearer scheme in any case', async () => {
    const { app } = buildApp();
    const { body } = await request(app).post('/auth/register').send(creds);
    await request(app).get('/private').set('Authorization', 'bearer ' + body.accessToken).expect(200);
  });
});

describe('email and hook failures', () => {
  const boom = async () => { throw new Error('smtp down'); };
  const tick = () => new Promise((resolve) => setImmediate(resolve));
  const quietly = async (fn) => {
    const original = console.error;
    console.error = () => {};
    try { await fn(); } finally { console.error = original; }
  };

  it('still registers and logs in when hooks fail', () => quietly(async () => {
    const hooks = { sendVerificationEmail: boom, sendPasswordResetEmail: boom, onRegister: boom, onLogin: boom };
    const { app } = buildApp({ hooks, emailVerification: true });
    await request(app).post('/auth/register').send(creds).expect(201);
    await request(app).post('/auth/login').send(creds).expect(200);
  }));

  it('replaces the verification link on resend', async () => {
    const { app, sent } = buildApp({ requireVerifiedEmail: true });
    await request(app).post('/auth/register').send(creds);
    const first = sent.verify.token;
    await request(app).post('/auth/resend-verification').send({ email: creds.email }).expect(200);
    await tick();
    assert.notEqual(sent.verify.token, first);
    await request(app).post('/auth/verify-email').send({ token: first }).expect(401);
    await request(app).post('/auth/verify-email').send({ token: sent.verify.token }).expect(204);
    await request(app).post('/auth/login').send(creds).expect(200);
  });

  it('responds the same for unknown and verified accounts, and sends nothing', async () => {
    const { app, sent } = buildApp({ emailVerification: true });
    await request(app).post('/auth/register').send(creds);
    await request(app).post('/auth/verify-email').send({ token: sent.verify.token }).expect(204);
    const last = sent.verify.token;
    const verified = await request(app).post('/auth/resend-verification').send({ email: creds.email }).expect(200);
    const unknown = await request(app).post('/auth/resend-verification').send({ email: 'ghost@x.com' }).expect(200);
    await tick();
    assert.deepEqual(verified.body, unknown.body);
    assert.equal(sent.verify.token, last);
  });

  it('requires the verification hook at startup', () => {
    assert.throws(() => buildApp({ emailVerification: true, hooks: { sendPasswordResetEmail: boom } }), /sendVerificationEmail/);
  });
});

describe('token cleanup', () => {
  it('removes expired tokens on a schedule', async () => {
    const adapter = memoryAdapter();
    const { app } = buildApp({ adapter, tokenCleanupIntervalMs: 10 });
    const { body } = await request(app).post('/auth/register').send(creds);
    const expired = { userId: body.user.id, tokenHash: 'expired', type: 'refresh', expiresAt: new Date(Date.now() - 1000), meta: {} };
    await adapter.saveToken(expired);
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(await adapter.findToken('expired', 'refresh'), null);
  });
});

describe('password reset links', () => {
  const tick = () => new Promise((resolve) => setImmediate(resolve));

  it('cancels a pending reset link when the password changes', async () => {
    const { app, sent } = buildApp();
    const { body } = await request(app).post('/auth/register').send(creds);
    await request(app).post('/auth/forgot-password').send({ email: creds.email });
    await tick();
    await request(app).post('/auth/change-password').set(...bearer(body.accessToken))
      .send({ currentPassword: creds.password, newPassword: 'changed999' }).expect(200);
    await request(app).post('/auth/reset-password').send({ token: sent.reset.token, newPassword: 'attacker99' }).expect(401);
  });

  it('treats a completed reset as proof of the email address', async () => {
    const { app, sent } = buildApp({ requireVerifiedEmail: true });
    await request(app).post('/auth/register').send(creds);
    await request(app).post('/auth/forgot-password').send({ email: creds.email });
    await tick();
    await request(app).post('/auth/reset-password').send({ token: sent.reset.token, newPassword: 'changed999' }).expect(204);
    await request(app).post('/auth/login').send({ email: creds.email, password: 'changed999' }).expect(200);
  });
});

describe('disabled accounts', () => {
  async function disabledUser() {
    const ctx = buildApp();
    const { body } = await request(ctx.app).post('/auth/register').send(creds);
    await ctx.auth.service.setDisabled(body.user.id, true);
    return { ...ctx, body };
  }

  it('blocks login, and only says so after the right password', async () => {
    const { app } = await disabledUser();
    const res = await request(app).post('/auth/login').send(creds).expect(403);
    assert.equal(res.body.error.code, 'ACCOUNT_DISABLED');
    await request(app).post('/auth/login').send({ ...creds, password: 'wrong1234' }).expect(401);
  });

  it('ends existing sessions at once', async () => {
    const { app, body } = await disabledUser();
    await request(app).get('/private').set(...bearer(body.accessToken)).expect(401);
    await request(app).post('/auth/refresh').send({ refreshToken: body.refreshToken }).expect(401);
  });

  it('sends no reset email', async () => {
    const { app, sent } = await disabledUser();
    await request(app).post('/auth/forgot-password').send({ email: creds.email }).expect(200);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(sent.reset, undefined);
  });

  it('can be re-enabled', async () => {
    const { app, auth, body } = await disabledUser();
    const user = await auth.service.setDisabled(body.user.id, false);
    assert.equal(user.disabled, false);
    await request(app).post('/auth/login').send(creds).expect(200);
  });
});

describe('admin api', () => {
  const adminCreds = { email: 'boss@example.com', password: 'secret123' };

  async function withAdmin(overrides) {
    const ctx = buildApp(overrides);
    await request(ctx.app).post('/auth/register').send(adminCreds);
    await ctx.auth.service.addRoleByEmail(adminCreds.email, 'admin');
    const { body: admin } = await request(ctx.app).post('/auth/login').send(adminCreds);
    const { body: member } = await request(ctx.app).post('/auth/register').send(creds);
    return { ...ctx, admin, member, as: bearer(admin.accessToken) };
  }

  it('is closed to anyone who is not an admin', async () => {
    const { app, member } = await withAdmin();
    await request(app).get('/auth/admin/users').expect(401);
    await request(app).get('/auth/admin/users').set(...bearer(member.accessToken)).expect(403);
  });

  it('lists users with paging and search, without private fields', async () => {
    const { app, as } = await withAdmin();
    const all = await request(app).get('/auth/admin/users').set(...as).expect(200);
    assert.equal(all.body.total, 2);
    assert.equal(all.body.users[0].passwordHash, undefined);
    const paged = await request(app).get('/auth/admin/users?limit=1&offset=1').set(...as).expect(200);
    assert.equal(paged.body.users.length, 1);
    const found = await request(app).get('/auth/admin/users?search=JANE').set(...as).expect(200);
    assert.deepEqual(found.body.users.map((u) => u.email), ['jane@example.com']);
  });

  it('ignores bad paging values and non-text search', async () => {
    const { app, as } = await withAdmin();
    const res = await request(app).get('/auth/admin/users?limit=9999&offset=-5&search[$ne]=x').set(...as).expect(200);
    assert.equal(res.body.limit, 100);
    assert.equal(res.body.offset, 0);
    assert.equal(res.body.total, 2);
  });

  it('reads one user and returns 404 for an unknown id', async () => {
    const { app, as, member } = await withAdmin();
    const res = await request(app).get('/auth/admin/users/' + member.user.id).set(...as).expect(200);
    assert.equal(res.body.user.email, 'jane@example.com');
    await request(app).get('/auth/admin/users/nope').set(...as).expect(404);
  });

  it('sets roles, which apply at once', async () => {
    const { app, as, member } = await withAdmin();
    await request(app).put('/auth/admin/users/' + member.user.id + '/roles').set(...as).send({ roles: ['admin'] }).expect(200);
    await request(app).get('/admin').set(...bearer(member.accessToken)).expect(200);
  });

  it('rejects invalid roles', async () => {
    const { app, as, member } = await withAdmin();
    for (const roles of ['admin', [1], [''], undefined]) {
      await request(app).put('/auth/admin/users/' + member.user.id + '/roles').set(...as).send({ roles }).expect(400);
    }
  });

  it('disables and enables accounts', async () => {
    const { app, as, member } = await withAdmin();
    const path = '/auth/admin/users/' + member.user.id;
    const res = await request(app).post(path + '/disable').set(...as).expect(200);
    assert.equal(res.body.user.disabled, true);
    await request(app).post('/auth/login').send(creds).expect(403);
    await request(app).post(path + '/enable').set(...as).expect(200);
    await request(app).post('/auth/login').send(creds).expect(200);
  });

  it('stops admins locking themselves out', async () => {
    const { app, as, admin } = await withAdmin();
    const path = '/auth/admin/users/' + admin.user.id;
    await request(app).put(path + '/roles').set(...as).send({ roles: ['user'] }).expect(400);
    await request(app).post(path + '/disable').set(...as).expect(400);
  });

  it('checks the database even with checkTokenVersion off', async () => {
    const { app, as, auth, admin } = await withAdmin({ checkTokenVersion: false });
    await auth.service.setRoles(admin.user.id, ['user']);
    await request(app).get('/auth/admin/users').set(...as).expect(403);
  });

  it('uses a custom admin role', async () => {
    const { app, auth } = buildApp({ adminRole: 'staff' });
    await request(app).post('/auth/register').send(adminCreds);
    await auth.service.addRoleByEmail(adminCreds.email, 'staff');
    const { body } = await request(app).post('/auth/login').send(adminCreds);
    await request(app).get('/auth/admin/users').set(...bearer(body.accessToken)).expect(200);
  });
});

describe('configuration', () => {
  it('fails fast on a bad adapter or weak secret', () => {
    assert.throws(() => createAuth({ adapter: {}, jwtSecret: 'x'.repeat(32) }), /missing methods/);
    assert.throws(() => createAuth({ adapter: memoryAdapter(), jwtSecret: 'short' }), /at least 32/);
    const placeholder = 'change-me-to-a-long-random-string-at-least-32-chars';
    assert.throws(() => createAuth({ adapter: memoryAdapter(), jwtSecret: placeholder }), /placeholder/);
  });

  it('refuses protected fields at signup', () => {
    assert.throws(() => buildApp({ allowedRegisterFields: ['phone', 'roles'] }), /cannot include: roles/);
  });
});
