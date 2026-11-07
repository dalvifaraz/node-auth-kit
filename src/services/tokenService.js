import jwt from 'jsonwebtoken';
import { randomToken, sha256 } from '../utils/crypto.js';
import { Errors } from '../utils/errors.js';

export const TOKEN_TYPES = {
  REFRESH: 'refresh',
  REFRESH_USED: 'refresh_used', // marker left by rotation, used to detect replays
  PASSWORD_RESET: 'password_reset',
  EMAIL_VERIFY: 'email_verify',
  EMAIL_CHANGE: 'email_change',
  LOGIN_CODE: 'login_code', // one-time code handed to the app after provider sign-in
};

export function createTokenService({ adapter, config }) {
  const { jwtSecret, accessTokenTtl, refreshTokenTtlMs, refreshReuseGraceMs, issuer, audience } = config;

  function signAccessToken(user) {
    return jwt.sign(
      { sub: String(user.id), email: user.email, roles: user.roles ?? [], tv: user.tokenVersion ?? 0 },
      jwtSecret,
      { expiresIn: accessTokenTtl, issuer, audience, algorithm: 'HS256' }
    );
  }

  /** Tokens signed with the current secret or, during a rotation, an older one are accepted. */
  function verifyAccessToken(token) {
    for (const secret of [jwtSecret, ...config.previousJwtSecrets]) {
      try {
        return jwt.verify(token, secret, { issuer, audience, algorithms: ['HS256'] });
      } catch {
        // try the next secret
      }
    }
    throw Errors.invalidToken();
  }

  /** Issue an opaque one-time token, store only its hash. Returns the raw token. */
  async function issueOpaqueToken(userId, type, ttlMs, meta = {}) {
    const raw = randomToken();
    await adapter.saveToken({
      userId: String(userId),
      tokenHash: sha256(raw),
      type,
      expiresAt: new Date(Date.now() + ttlMs),
      meta,
    });
    return raw;
  }

  /** Validate + delete (single use). Returns the stored record. */
  async function consumeOpaqueToken(raw, type) {
    if (!raw || typeof raw !== 'string') throw Errors.invalidToken();
    const record = await adapter.consumeToken(sha256(raw), type);
    if (!record) throw Errors.invalidToken();
    if (new Date(record.expiresAt).getTime() < Date.now()) throw Errors.invalidToken();
    return record;
  }

  /** Single use, like consumeOpaqueToken. Calls onReuse(userId) if a used token is replayed after the grace period. */
  async function consumeRefreshToken(raw, onReuse) {
    if (!raw || typeof raw !== 'string') throw Errors.invalidToken();
    const tokenHash = sha256(raw);
    const record = await adapter.consumeToken(tokenHash, TOKEN_TYPES.REFRESH);
    if (!record) {
      const used = await adapter.findToken(tokenHash, TOKEN_TYPES.REFRESH_USED);
      if (used && Date.now() - used.meta.usedAt >= refreshReuseGraceMs) await onReuse(used.userId);
      throw Errors.invalidToken();
    }
    if (new Date(record.expiresAt).getTime() < Date.now()) throw Errors.invalidToken();
    await adapter.saveToken({
      userId: record.userId,
      tokenHash,
      type: TOKEN_TYPES.REFRESH_USED,
      expiresAt: record.expiresAt,
      meta: { usedAt: Date.now() },
    });
    return record;
  }

  async function issueTokenPair(user, meta = {}) {
    const accessToken = signAccessToken(user);
    const refreshToken = await issueOpaqueToken(user.id, TOKEN_TYPES.REFRESH, refreshTokenTtlMs, meta);
    return { accessToken, refreshToken, tokenType: 'Bearer', expiresIn: accessTokenTtl };
  }

  return {
    signAccessToken,
    verifyAccessToken,
    issueOpaqueToken,
    consumeOpaqueToken,
    consumeRefreshToken,
    issueTokenPair,
    revokeRefreshToken: (raw) => adapter.deleteToken(sha256(raw)),
    revokeAllForUser: (userId, type = TOKEN_TYPES.REFRESH) => adapter.deleteUserTokens(String(userId), type),
  };
}
