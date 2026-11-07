import crypto from 'node:crypto';
import { randomToken } from '../utils/crypto.js';
import { Errors } from '../utils/errors.js';
import { parseCookies } from '../middleware/sessionCookie.js';
import { PROVIDERS } from '../services/oauthProviders.js';

const STATE_COOKIE = 'auth_oauth';
const STATE_TTL_MS = 10 * 60 * 1000;
const FETCH_TIMEOUT_MS = 10 * 1000;
const KNOWN_ERRORS = { ACCOUNT_DISABLED: 'account_disabled', EMAIL_NOT_VERIFIED: 'email_not_verified' };

/**
 * Checks the oauth option. Returns null when sign-in with providers is off.
 *   { publicUrl, redirectUrl, providers: { google: { clientId, clientSecret }, ... }, cookieSecure }
 */
export function createOAuth(options, jwtSecret) {
  if (!options) return null;
  const { publicUrl, redirectUrl, providers = {}, cookieSecure = true } = options;
  if (!URL.canParse(publicUrl ?? '')) {
    throw new Error('createAuth: `oauth.publicUrl` must be the full URL where the auth router is mounted');
  }
  const redirects = [redirectUrl].flat().filter(Boolean);
  if (!redirects.length || !redirects.every((url) => URL.canParse(url))) {
    throw new Error('createAuth: `oauth.redirectUrl` must be a full URL, or a list of them');
  }

  const configured = {};
  for (const [name, settings] of Object.entries(providers)) {
    if (!settings) continue;
    const provider = { ...PROVIDERS[name], ...settings };
    if (!provider.clientId || !provider.clientSecret) {
      throw new Error(`createAuth: \`oauth.providers.${name}\` needs clientId and clientSecret`);
    }
    if (!provider.authorizeUrl || !provider.tokenUrl || typeof provider.getProfile !== 'function') {
      throw new Error(`createAuth: unknown sign-in provider "${name}"; give authorizeUrl, tokenUrl and getProfile`);
    }
    configured[name] = provider;
  }
  if (!Object.keys(configured).length) throw new Error('createAuth: `oauth.providers` needs at least one provider');

  // A separate key, so a state cookie can never be mistaken for anything else signed with jwtSecret.
  const key = crypto.createHash('sha256').update(`oauth-state:${jwtSecret}`).digest();
  return { publicUrl: publicUrl.replace(/\/+$/, ''), redirects, providers: configured, cookieSecure, key };
}

const safeEqual = (a, b) => {
  const [x, y] = [Buffer.from(String(a)), Buffer.from(String(b))];
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

async function fetchJson(url, accessToken) {
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json', 'User-Agent': 'node-auth-kit' },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`${url} answered ${res.status}`);
  return res.json();
}

async function exchangeCode(provider, { code, redirectUri, verifier }) {
  const res = await fetch(provider.tokenUrl, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'node-auth-kit' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: provider.clientId,
      client_secret: provider.clientSecret,
      code_verifier: verifier,
    }),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !body.access_token) throw new Error(`token exchange failed (${res.status}${body.error ? `: ${body.error}` : ''})`);
  return body.access_token;
}

/**
 * Sign-in with Google, GitHub or another OAuth provider:
 *   GET  /oauth/:provider            sends the browser to the provider
 *   GET  /oauth/:provider/callback   the provider sends it back; we redirect to the app with ?code= or ?error=
 *   POST /oauth/exchange             the app trades that one-time code for a session
 */
export function addOAuthRoutes(r, { oauth, service, limit, wrap, sendSession, wantsCookie, meta }) {
  const sign = (data) => crypto.createHmac('sha256', oauth.key).update(data).digest('base64url');
  const encode = (payload) => {
    const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return `${data}.${sign(data)}`;
  };
  const decode = (value) => {
    if (typeof value !== 'string') return null;
    const [data, signature] = value.split('.');
    if (!data || !signature || !safeEqual(signature, sign(data))) return null;
    try {
      const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
      return payload.exp > Date.now() ? payload : null;
    } catch {
      return null;
    }
  };

  // Lax, because the browser arrives back from the provider's site.
  const cookieOptions = (req) => ({ httpOnly: true, secure: oauth.cookieSecure, sameSite: 'lax', path: `${req.baseUrl}/oauth` });
  const callbackUrl = (name) => `${oauth.publicUrl}/oauth/${name}/callback`;
  const backTo = (res, redirect, params) => {
    const url = new URL(redirect);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
    res.redirect(302, url.toString());
  };

  r.get('/oauth/:provider', (req, res, next) => {
    const name = req.params.provider;
    const provider = Object.hasOwn(oauth.providers, name) ? oauth.providers[name] : null;
    if (!provider) return next(Errors.notFound('Unknown sign-in provider'));
    const asked = req.query.redirect;
    if (asked !== undefined && !oauth.redirects.includes(asked)) {
      return next(Errors.validation('That redirect is not in oauth.redirectUrl'));
    }

    const state = randomToken(32);
    const verifier = randomToken(48);
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    const saved = { provider: name, state, verifier, redirect: asked ?? oauth.redirects[0], exp: Date.now() + STATE_TTL_MS };
    res.cookie(STATE_COOKIE, encode(saved), { ...cookieOptions(req), maxAge: STATE_TTL_MS });

    const url = new URL(provider.authorizeUrl);
    for (const [k, v] of Object.entries({
      client_id: provider.clientId,
      redirect_uri: callbackUrl(name),
      response_type: 'code',
      scope: provider.scope,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    })) url.searchParams.set(k, v);
    res.redirect(302, url.toString());
  });

  r.get('/oauth/:provider/callback', wrap(async (req, res) => {
    const name = req.params.provider;
    const saved = decode(parseCookies(req.headers.cookie)[STATE_COOKIE]);
    res.clearCookie(STATE_COOKIE, cookieOptions(req));
    const redirect = saved?.redirect ?? oauth.redirects[0];

    // The state must come back to the same browser that started, or this is a forged login.
    const stateOk = saved && saved.provider === name && typeof req.query.state === 'string' && safeEqual(req.query.state, saved.state);
    if (!stateOk) return backTo(res, redirect, { error: 'invalid_state' });
    if (req.query.error) return backTo(res, redirect, { error: 'access_denied' });
    if (typeof req.query.code !== 'string') return backTo(res, redirect, { error: 'invalid_request' });

    try {
      const provider = oauth.providers[name];
      const accessToken = await exchangeCode(provider, { code: req.query.code, redirectUri: callbackUrl(name), verifier: saved.verifier });
      const profile = await provider.getProfile(accessToken, fetchJson, provider);
      const user = await service.signInWithProvider({ ...profile, provider: name }, meta(req));
      backTo(res, redirect, { code: await service.createLoginCode(user.id) });
    } catch (err) {
      const known = KNOWN_ERRORS[err?.code];
      if (!known) console.error(`[auth] ${name} sign-in failed:`, err);
      backTo(res, redirect, { error: known ?? 'oauth_failed' });
    }
  }));

  r.post('/oauth/exchange', limit, wrap(async (req, res) => {
    const session = await service.exchangeLoginCode(req.body?.code, meta(req));
    sendSession(req, res, session, { useCookie: wantsCookie(req) });
  }));
}
