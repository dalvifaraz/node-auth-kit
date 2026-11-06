import jwt from 'jsonwebtoken';
import { randomToken, sha256 } from '../utils/crypto.js';
import { Errors } from '../utils/errors.js';

export const TOKEN_TYPES = {
  REFRESH: 'refresh',
  PASSWORD_RESET: 'password_reset',
  EMAIL_VERIFY: 'email_verify',
};

export function createTokenService({ adapter, config }) {
  const { jwtSecret, accessTokenTtl, refreshTokenTtlMs, issuer, audience } = config;

  function signAccessToken(user) {
    return jwt.sign(
      { sub: String(user.id), email: user.email, roles: user.roles ?? [] },
      jwtSecret,
      { expiresIn: accessTokenTtl, issuer, audience, algorithm: 'HS256' }
    );
  }

  function verifyAccessToken(token) {
    try {
      return jwt.verify(token, jwtSecret, { issuer, audience, algorithms: ['HS256'] });
    } catch {
      throw Errors.invalidToken();
    }
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
    issueTokenPair,
    revokeRefreshToken: (raw) => adapter.deleteToken(sha256(raw)),
    revokeAllForUser: (userId, type = TOKEN_TYPES.REFRESH) => adapter.deleteUserTokens(String(userId), type),
  };
}
