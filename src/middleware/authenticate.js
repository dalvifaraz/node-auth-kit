import { Errors } from '../utils/errors.js';

/** Verifies `Authorization: Bearer <accessToken>` and sets req.auth = { userId, email, roles }. */
export function createAuthenticate(tokens) {
  return function authenticate(req, _res, next) {
    const header = req.headers.authorization ?? '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) return next(Errors.unauthorized('Missing bearer token'));
    try {
      const payload = tokens.verifyAccessToken(token);
      req.auth = { userId: payload.sub, email: payload.email, roles: payload.roles ?? [] };
      next();
    } catch (err) {
      next(err);
    }
  };
}

/** Use after authenticate: requireRoles('admin') */
export const requireRoles = (...roles) => (req, _res, next) => {
  const has = req.auth?.roles ?? [];
  if (!roles.some((r) => has.includes(r))) return next(Errors.forbidden('Insufficient role'));
  next();
};
