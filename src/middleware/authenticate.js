import { Errors } from '../utils/errors.js';

/**
 * Verifies `Authorization: Bearer <accessToken>` and sets req.auth = { userId, email, roles }.
 * With an adapter, also rejects revoked tokens and reads current roles from the database.
 */
export function createAuthenticate(tokens, adapter = null) {
  return async function authenticate(req, _res, next) {
    const header = req.headers.authorization ?? '';
    const [scheme, token] = header.split(' ');
    if (scheme?.toLowerCase() !== 'bearer' || !token) return next(Errors.unauthorized('Missing bearer token'));
    try {
      const payload = tokens.verifyAccessToken(token);
      let roles = payload.roles ?? [];
      if (adapter) {
        const user = await adapter.findUserById(payload.sub);
        if (!user || user.disabled || (user.tokenVersion ?? 0) !== (payload.tv ?? 0)) throw Errors.invalidToken();
        roles = user.roles ?? [];
      }
      req.auth = { userId: payload.sub, email: payload.email, roles };
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
