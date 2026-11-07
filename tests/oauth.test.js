import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import express from 'express';
import request from 'supertest';
import { createAuth, memoryAdapter, oauthConfigFromEnv } from '../src/index.js';

/** A stand-in for Google and GitHub, so the whole flow runs without real accounts. */
function fakeProvider() {
  const fake = {
    challenge: null,
    tokenCalls: 0,
    google: { sub: 'g-1', email: 'jane@example.com', email_verified: true, name: 'Jane' },
    githubUser: { id: 42, login: 'jane', name: null },
    githubEmails: [
      { email: 'old@example.com', primary: false, verified: true },
      { email: 'jane@example.com', primary: true, verified: true },
    ],
  };
  const app = express();
  app.use(express.urlencoded({ extended: false }));
  app.post(['/token', '/gh/token'], (req, res) => {
    fake.tokenCalls++;
    const pkce = crypto.createHash('sha256').update(req.body.code_verifier ?? '').digest('base64url');
    const ok = req.body.code === 'good-code' && req.body.client_secret === 'secret' && pkce === fake.challenge
      && req.body.redirect_uri === fake.expectedRedirectUri;
    if (!ok) return res.json({ error: 'bad_verification_code' });
    res.json({ access_token: 'provider-token' });
  });
  const authorized = (req, res, next) => (req.get('authorization') === 'Bearer provider-token' ? next() : res.sendStatus(401));
  app.get('/userinfo', authorized, (_req, res) => res.json(fake.google));
  app.get('/gh/api/user', authorized, (_req, res) => res.json(fake.githubUser));
  app.get('/gh/api/user/emails', authorized, (_req, res) => res.json(fake.githubEmails));
  return { fake, app };
}

describe('sign-in with providers', () => {
  let server, base, fake;
  before(async () => {
    const provider = fakeProvider();
    fake = provider.fake;
    server = provider.app.listen(0);
    await new Promise((resolve) => server.once('listening', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  });
  after(() => server.close());

  const frontend = 'https://app.example.com/signed-in';
  function build(overrides = {}) {
    const adapter = overrides.adapter ?? memoryAdapter();
    const sent = {};
    const auth = createAuth({
      adapter,
      jwtSecret: 'test-secret-test-secret-test-secret-1234',
      bcryptRounds: 4,
      rateLimiter: false,
      hooks: { sendPasswordResetEmail: ({ token }) => { sent.reset = token; } },
      oauth: {
        publicUrl: 'https://api.example.com/auth/',
        redirectUrl: [frontend, 'myapp://signed-in'],
        providers: {
          google: { clientId: 'google-id', clientSecret: 'secret', authorizeUrl: 'https://accounts.example/authorize', tokenUrl: `${base}/token`, userInfoUrl: `${base}/userinfo` },
          github: { clientId: 'github-id', clientSecret: 'secret', tokenUrl: `${base}/gh/token`, apiUrl: `${base}/gh/api` },
        },
      },
      ...overrides,
    });
    const app = express();
    app.use('/auth', auth.router);
    app.get('/private', auth.authenticate, (req, res) => res.json({ id: req.auth.userId }));
    app.use(auth.errorHandler);
    return { app, auth, adapter, sent };
  }

  /** Runs the browser part: start, come back from the provider, land on the frontend. */
  async function signIn(app, { provider = 'google', redirect, code = 'good-code', tamper } = {}) {
    const query = redirect ? `?redirect=${encodeURIComponent(redirect)}` : '';
    const start = await request(app).get(`/auth/oauth/${provider}${query}`).expect(302);
    const to = new URL(start.headers.location);
    fake.challenge = to.searchParams.get('code_challenge');
    fake.expectedRedirectUri = `https://api.example.com/auth/oauth/${provider}/callback`;
    let state = to.searchParams.get('state');
    let cookie = start.headers['set-cookie'][0].split(';')[0];
    if (tamper === 'state') state = 'forged';
    if (tamper === 'cookie') cookie = 'auth_oauth=forged.value';
    const back = await request(app).get(`/auth/oauth/${provider}/callback?code=${code}&state=${state}`).set('Cookie', cookie).expect(302);
    return { start, to, back, landed: new URL(back.headers.location) };
  }
  const exchange = (app, code, body = {}) => request(app).post('/auth/oauth/exchange').send({ code, ...body });

  it('sends the browser to the provider with PKCE and a signed state cookie', async () => {
    const { app } = build();
    const { start, to } = await signIn(app);
    assert.equal(to.origin + to.pathname, 'https://accounts.example/authorize');
    assert.equal(to.searchParams.get('client_id'), 'google-id');
    assert.equal(to.searchParams.get('redirect_uri'), 'https://api.example.com/auth/oauth/google/callback');
    assert.equal(to.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(to.searchParams.get('scope'), 'openid email profile');
    const cookie = start.headers['set-cookie'][0];
    for (const attribute of ['HttpOnly', 'Secure', 'SameSite=Lax', 'Path=/auth/oauth']) assert.ok(cookie.includes(attribute), attribute);
  });

  it('creates a verified account without a password, then signs it in', async () => {
    const { app } = build();
    const { landed, back } = await signIn(app);
    assert.equal(landed.origin + landed.pathname, frontend);
    assert.equal(back.headers['cache-control'], 'no-store');
    const res = await exchange(app, landed.searchParams.get('code')).expect(200);
    assert.equal(res.body.user.email, 'jane@example.com');
    assert.equal(res.body.user.name, 'Jane');
    assert.equal(res.body.user.emailVerified, true);
    assert.equal(res.body.user.hasPassword, false);
    await request(app).get('/private').set('Authorization', 'Bearer ' + res.body.accessToken).expect(200);
  });

  it('signs the same person into the same account next time', async () => {
    const { app } = build();
    const first = await exchange(app, (await signIn(app)).landed.searchParams.get('code'));
    const second = await exchange(app, (await signIn(app)).landed.searchParams.get('code'));
    assert.equal(second.body.user.id, first.body.user.id);
  });

  it('accepts each login code once', async () => {
    const { app } = build();
    const code = (await signIn(app)).landed.searchParams.get('code');
    await exchange(app, code).expect(200);
    await exchange(app, code).expect(401);
    await exchange(app, 'made-up').expect(401);
  });

  it('links to an existing verified account with the same email', async () => {
    const { app, adapter } = build();
    const { body } = await request(app).post('/auth/register').send({ email: 'jane@example.com', password: 'secret123' });
    await adapter.updateUser(body.user.id, { emailVerified: true });
    const res = await exchange(app, (await signIn(app)).landed.searchParams.get('code')).expect(200);
    assert.equal(res.body.user.id, body.user.id);
    assert.equal(res.body.user.hasPassword, true);
    await request(app).post('/auth/login').send({ email: 'jane@example.com', password: 'secret123' }).expect(200);
  });

  it('takes an unverified account back from whoever registered it first', async () => {
    const { app } = build();
    const squatter = await request(app).post('/auth/register').send({ email: 'jane@example.com', password: 'squat1234' });
    const res = await exchange(app, (await signIn(app)).landed.searchParams.get('code')).expect(200);
    assert.equal(res.body.user.id, squatter.body.user.id);
    assert.equal(res.body.user.hasPassword, false);
    await request(app).post('/auth/login').send({ email: 'jane@example.com', password: 'squat1234' }).expect(401);
    await request(app).get('/private').set('Authorization', 'Bearer ' + squatter.body.accessToken).expect(401);
    await request(app).post('/auth/refresh').send({ refreshToken: squatter.body.refreshToken }).expect(401);
  });

  it('refuses an email the provider has not verified', async () => {
    const { app, adapter } = build();
    fake.google = { ...fake.google, email_verified: false };
    try {
      const { landed } = await signIn(app);
      assert.equal(landed.searchParams.get('error'), 'email_not_verified');
      assert.equal(await adapter.findUserByEmail('jane@example.com'), null);
    } finally {
      fake.google = { ...fake.google, email_verified: true };
    }
  });

  it('rejects a forged state or state cookie without calling the provider', async () => {
    const { app } = build();
    for (const tamper of ['state', 'cookie']) {
      const calls = fake.tokenCalls;
      const { landed } = await signIn(app, { tamper });
      assert.equal(landed.searchParams.get('error'), 'invalid_state', tamper);
      assert.equal(fake.tokenCalls, calls, tamper);
    }
  });

  it('rejects a state cookie from another app', async () => {
    const other = build({ jwtSecret: 'other-secret-other-secret-other-12345' });
    const { app } = build();
    const start = await request(other.app).get('/auth/oauth/google').expect(302);
    const state = new URL(start.headers.location).searchParams.get('state');
    const back = await request(app).get('/auth/oauth/google/callback?code=good-code&state=' + state)
      .set('Cookie', start.headers['set-cookie'][0].split(';')[0]).expect(302);
    assert.equal(new URL(back.headers.location).searchParams.get('error'), 'invalid_state');
  });

  it('reports a failed code exchange as oauth_failed', async () => {
    const { app } = build();
    const original = console.error;
    console.error = () => {};
    try {
      const { landed } = await signIn(app, { code: 'bad-code' });
      assert.equal(landed.searchParams.get('error'), 'oauth_failed');
    } finally {
      console.error = original;
    }
  });

  it('passes on a refusal at the provider', async () => {
    const { app } = build();
    const start = await request(app).get('/auth/oauth/google').expect(302);
    const state = new URL(start.headers.location).searchParams.get('state');
    const back = await request(app).get('/auth/oauth/google/callback?error=access_denied&state=' + state)
      .set('Cookie', start.headers['set-cookie'][0].split(';')[0]).expect(302);
    assert.equal(new URL(back.headers.location).searchParams.get('error'), 'access_denied');
  });

  it('keeps disabled accounts out', async () => {
    const { app, auth } = build();
    const first = await exchange(app, (await signIn(app)).landed.searchParams.get('code'));
    await auth.service.setDisabled(first.body.user.id, true);
    const { landed } = await signIn(app);
    assert.equal(landed.searchParams.get('error'), 'account_disabled');
  });

  it('returns only to allowed redirects', async () => {
    const { app } = build();
    const { landed } = await signIn(app, { redirect: 'myapp://signed-in' });
    assert.equal(landed.protocol, 'myapp:');
    assert.ok(landed.searchParams.get('code'));
    await request(app).get('/auth/oauth/google?redirect=' + encodeURIComponent('https://evil.example')).expect(400);
  });

  it('returns 404 for an unknown provider', async () => {
    const { app } = build();
    await request(app).get('/auth/oauth/facebook').expect(404);
    await request(app).get('/auth/oauth/constructor').expect(404);
  });

  it('signs in with GitHub using the primary verified email', async () => {
    const { app } = build();
    const res = await exchange(app, (await signIn(app, { provider: 'github' })).landed.searchParams.get('code')).expect(200);
    assert.equal(res.body.user.email, 'jane@example.com');
    assert.equal(res.body.user.name, 'jane');
  });

  it('refuses GitHub when no primary email is verified', async () => {
    const { app } = build();
    const saved = fake.githubEmails;
    fake.githubEmails = [{ email: 'jane@example.com', primary: true, verified: false }];
    try {
      const { landed } = await signIn(app, { provider: 'github' });
      assert.equal(landed.searchParams.get('error'), 'email_not_verified');
    } finally {
      fake.githubEmails = saved;
    }
  });

  it('works with cookie login', async () => {
    const { app } = build({ cookie: true });
    const res = await exchange(app, (await signIn(app)).landed.searchParams.get('code')).expect(200);
    assert.equal(res.body.refreshToken, undefined);
    assert.match(res.headers['set-cookie'][0], /^auth_refresh=/);
  });

  describe('accounts without a password', () => {
    async function oauthUser(overrides) {
      const ctx = build(overrides);
      const res = await exchange(ctx.app, (await signIn(ctx.app)).landed.searchParams.get('code'));
      return { ...ctx, session: res.body, as: ['Authorization', 'Bearer ' + res.body.accessToken] };
    }

    it('cannot log in with a password', async () => {
      const { app } = await oauthUser();
      await request(app).post('/auth/login').send({ email: 'jane@example.com', password: 'anything1' }).expect(401);
    });

    it('sets a password through forgot-password, not change-password', async () => {
      const { app, sent, as } = await oauthUser();
      const res = await request(app).post('/auth/change-password').set(...as).send({ newPassword: 'chosen123' }).expect(400);
      assert.match(res.body.error.message, /forgot password/);
      await request(app).post('/auth/forgot-password').send({ email: 'jane@example.com' });
      await new Promise((resolve) => setImmediate(resolve));
      await request(app).post('/auth/reset-password').send({ token: sent.reset, newPassword: 'chosen123' }).expect(204);
      await request(app).post('/auth/login').send({ email: 'jane@example.com', password: 'chosen123' }).expect(200);
    });

    it('must set a password before changing email', async () => {
      const hooks = { sendPasswordResetEmail: () => {}, sendEmailChangeEmail: () => {} };
      const { app, as } = await oauthUser({ hooks });
      const res = await request(app).post('/auth/change-email').set(...as).send({ newEmail: 'new@example.com' }).expect(400);
      assert.match(res.body.error.message, /Set a password first/);
    });

    it('deletes the account after the email is typed out', async () => {
      const { app, as } = await oauthUser();
      await request(app).delete('/auth/me').set(...as).send({}).expect(400);
      await request(app).delete('/auth/me').set(...as).send({ confirmEmail: 'Jane@Example.com' }).expect(204);
      const again = await exchange(app, (await signIn(app)).landed.searchParams.get('code')).expect(200);
      assert.equal(again.body.user.hasPassword, false);
    });
  });

  it('checks settings at startup', () => {
    const oauth = (o) => () => build({ oauth: { publicUrl: 'https://api.example.com/auth', redirectUrl: frontend, providers: { google: { clientId: 'a', clientSecret: 'b' } }, ...o } });
    assert.doesNotThrow(oauth({}));
    assert.throws(oauth({ publicUrl: 'api.example.com' }), /publicUrl/);
    assert.throws(oauth({ redirectUrl: undefined }), /redirectUrl/);
    assert.throws(oauth({ providers: {} }), /at least one/);
    assert.throws(oauth({ providers: { google: { clientId: 'a' } } }), /clientSecret/);
    assert.throws(oauth({ providers: { myspace: { clientId: 'a', clientSecret: 'b' } } }), /unknown sign-in provider/);
  });

  it('reads settings from the environment', () => {
    assert.equal(oauthConfigFromEnv({}), null);
    const config = oauthConfigFromEnv({
      GOOGLE_CLIENT_ID: 'g', GOOGLE_CLIENT_SECRET: 'gs', AUTH_PUBLIC_URL: 'https://api.example.com/auth', OAUTH_REDIRECT_URL: frontend,
    });
    assert.deepEqual(config, {
      publicUrl: 'https://api.example.com/auth', redirectUrl: frontend, providers: { google: { clientId: 'g', clientSecret: 'gs' } }, cookieSecure: true,
    });
  });
});
