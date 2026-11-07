import express from 'express';
import { AuthError } from '../utils/errors.js';
import { addOAuthRoutes } from './oauthRoutes.js';

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const meta = (req) => ({ ip: req.ip, userAgent: req.get('user-agent') ?? null });

export function createAuthRouter({ service, authenticate, adminGuard, rateLimiter, cookies, oauth }) {
  const r = express.Router();
  r.use(express.json({ limit: '10kb' }));
  const limit = rateLimiter ?? ((_req, _res, next) => next());

  /** Answers with the session, moving the refresh token into the cookie when asked to. */
  const sendSession = (req, res, session, { status = 200, useCookie = false } = {}) => {
    if (!useCookie || !session.refreshToken) return res.status(status).json(session);
    const { refreshToken, ...rest } = session;
    cookies.set(req, res, refreshToken);
    res.status(status).json(rest);
  };
  const wantsCookie = (req) => Boolean(cookies) && req.body?.tokenDelivery !== 'body';

  r.post('/register', limit, wrap(async (req, res) => {
    const session = await service.register(req.body ?? {}, meta(req));
    sendSession(req, res, session, { status: 201, useCookie: wantsCookie(req) });
  }));

  r.post('/login', limit, wrap(async (req, res) => {
    const session = await service.login(req.body ?? {}, meta(req));
    sendSession(req, res, session, { useCookie: wantsCookie(req) });
  }));

  r.post('/refresh', wrap(async (req, res) => {
    const bodyToken = req.body?.refreshToken;
    const cookieToken = cookies?.read(req);
    const useCookie = bodyToken === undefined && cookieToken !== undefined;
    if (useCookie) cookies.assertOrigin(req);
    sendSession(req, res, await service.refresh(bodyToken ?? cookieToken, meta(req)), { useCookie });
  }));

  r.post('/logout', wrap(async (req, res) => {
    const cookieToken = cookies?.read(req);
    if (cookieToken !== undefined) cookies.assertOrigin(req);
    await service.logout(req.body?.refreshToken ?? cookieToken);
    cookies?.clear(req, res);
    res.status(204).end();
  }));

  r.post('/logout-all', authenticate, wrap(async (req, res) => {
    await service.logoutAll(req.auth.userId);
    cookies?.clear(req, res);
    res.status(204).end();
  }));

  r.get('/me', authenticate, wrap(async (req, res) => {
    res.json({ user: await service.me(req.auth.userId) });
  }));

  r.delete('/me', authenticate, limit, wrap(async (req, res) => {
    await service.deleteAccount(req.auth.userId, req.body ?? {});
    cookies?.clear(req, res);
    res.status(204).end();
  }));

  r.post('/change-email', authenticate, limit, wrap(async (req, res) => {
    await service.requestEmailChange(req.auth.userId, req.body ?? {});
    res.json({ message: 'A confirmation link has been sent to the new address.' });
  }));

  r.post('/confirm-email-change', limit, wrap(async (req, res) => {
    await service.confirmEmailChange(req.body ?? {});
    res.status(204).end();
  }));

  r.post('/change-password', authenticate, limit, wrap(async (req, res) => {
    const session = await service.changePassword(req.auth.userId, req.body ?? {});
    sendSession(req, res, session, { useCookie: cookies?.read(req) !== undefined });
  }));

  r.post('/forgot-password', limit, wrap(async (req, res) => {
    await service.forgotPassword(req.body ?? {});
    res.json({ message: 'If that email exists, a reset link has been sent.' });
  }));

  r.post('/reset-password', limit, wrap(async (req, res) => {
    await service.resetPassword(req.body ?? {});
    res.status(204).end();
  }));

  r.post('/resend-verification', limit, wrap(async (req, res) => {
    await service.resendVerification(req.body ?? {});
    res.json({ message: 'If that account needs verifying, an email has been sent.' });
  }));

  r.post('/verify-email', wrap(async (req, res) => {
    await service.verifyEmail(req.body ?? {});
    res.status(204).end();
  }));

  r.get('/admin/users', adminGuard, wrap(async (req, res) => {
    res.json(await service.listUsers(req.query));
  }));

  r.get('/admin/users/:id', adminGuard, wrap(async (req, res) => {
    res.json({ user: await service.me(req.params.id) });
  }));

  r.put('/admin/users/:id/roles', adminGuard, wrap(async (req, res) => {
    res.json({ user: await service.setRoles(req.params.id, req.body?.roles, { actorId: req.auth.userId }) });
  }));

  r.post('/admin/users/:id/disable', adminGuard, wrap(async (req, res) => {
    res.json({ user: await service.setDisabled(req.params.id, true, { actorId: req.auth.userId }) });
  }));

  r.post('/admin/users/:id/enable', adminGuard, wrap(async (req, res) => {
    res.json({ user: await service.setDisabled(req.params.id, false, { actorId: req.auth.userId }) });
  }));

  r.delete('/admin/users/:id', adminGuard, wrap(async (req, res) => {
    await service.deleteUser(req.params.id, { actorId: req.auth.userId });
    res.status(204).end();
  }));

  if (oauth) addOAuthRoutes(r, { oauth, service, limit, wrap, sendSession, wantsCookie, meta });

  // Error handler scoped to this router — consistent JSON error shape.
  // eslint-disable-next-line no-unused-vars
  r.use((err, _req, res, _next) => {
    if (err instanceof AuthError) {
      return res.status(err.status).json({ error: { code: err.code, message: err.message } });
    }
    if (err?.type === 'entity.parse.failed') {
      return res.status(400).json({ error: { code: 'BAD_JSON', message: 'Malformed JSON body' } });
    }
    if (err?.type === 'entity.too.large') {
      return res.status(413).json({ error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large' } });
    }
    if (err?.status >= 400 && err?.status < 500) {
      return res.status(err.status).json({ error: { code: 'BAD_REQUEST', message: 'Invalid request' } });
    }
    console.error('[auth] unexpected error:', err);
    res.status(500).json({ error: { code: 'INTERNAL', message: 'Internal server error' } });
  });

  return r;
}
