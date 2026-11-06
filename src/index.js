import { createTokenService } from './services/tokenService.js';
import { createAuthService } from './services/authService.js';
import { createAuthenticate, requireRoles } from './middleware/authenticate.js';
import { createRateLimiter } from './middleware/rateLimit.js';
import { createAuthRouter } from './routes/authRoutes.js';
import { defaultPasswordPolicy } from './utils/validate.js';
import { AuthError } from './utils/errors.js';

const REQUIRED_ADAPTER_METHODS = [
  'createUser', 'findUserByEmail', 'findUserById', 'updateUser', 'listUsers',
  'saveToken', 'findToken', 'consumeToken', 'deleteToken', 'deleteUserTokens', 'deleteExpiredTokens',
];

// Fields a client must never be able to set at signup.
const PROTECTED_USER_FIELDS = [
  'id', 'email', 'passwordHash', 'roles', 'emailVerified', 'tokenVersion', 'disabled', 'createdAt', 'updatedAt',
];

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

/**
 * Build a complete auth module.
 *
 * @param {object}  options
 * @param {object}  options.adapter        Database adapter (see src/adapters/README.md)
 * @param {string}  options.jwtSecret      Secret for signing access tokens (min 32 chars)
 * @param {object} [options.hooks]         { sendPasswordResetEmail, sendVerificationEmail, onRegister, onLogin }
 * @returns {{ router, authenticate, requireRoles, service, tokens, errorHandler }}
 */
export function createAuth(options = {}) {
  const { adapter, hooks = {} } = options;

  if (!adapter) throw new Error('createAuth: `adapter` is required');
  const missing = REQUIRED_ADAPTER_METHODS.filter((m) => typeof adapter[m] !== 'function');
  if (missing.length) throw new Error(`createAuth: adapter is missing methods: ${missing.join(', ')}`);
  if (!options.jwtSecret || options.jwtSecret.length < 32) {
    throw new Error('createAuth: `jwtSecret` must be at least 32 characters');
  }
  if (/change-?me/i.test(options.jwtSecret)) {
    throw new Error('createAuth: `jwtSecret` is still a placeholder; generate one with the command in .env.example');
  }

  if (options.requireVerifiedEmail && options.emailVerification === false) {
    throw new Error('createAuth: `requireVerifiedEmail` needs `emailVerification`');
  }

  const unsafe = (options.allowedRegisterFields ?? []).filter((f) => PROTECTED_USER_FIELDS.includes(f));
  if (unsafe.length) {
    throw new Error(`createAuth: \`allowedRegisterFields\` cannot include: ${unsafe.join(', ')}`);
  }

  const config = {
    jwtSecret: options.jwtSecret,
    accessTokenTtl: options.accessTokenTtl ?? '15m',
    refreshTokenTtlMs: options.refreshTokenTtlMs ?? 30 * DAY,
    refreshReuseGraceMs: options.refreshReuseGraceMs ?? 10 * 1000,
    resetTokenTtlMs: options.resetTokenTtlMs ?? 60 * 60 * 1000,
    verifyTokenTtlMs: options.verifyTokenTtlMs ?? 2 * DAY,
    issuer: options.issuer ?? 'node-auth-kit',
    audience: options.audience ?? 'node-auth-kit',
    bcryptRounds: options.bcryptRounds ?? 12,
    checkTokenVersion: options.checkTokenVersion ?? true,
    defaultRoles: options.defaultRoles ?? ['user'],
    adminRole: options.adminRole ?? 'admin',
    allowedRegisterFields: options.allowedRegisterFields ?? [], // extra fields accepted on /register
    publicUserFields: options.publicUserFields ?? [], // extra user fields returned to clients
    passwordPolicy: options.passwordPolicy ?? defaultPasswordPolicy,
    emailVerification: options.emailVerification ?? options.requireVerifiedEmail ?? false,
    requireVerifiedEmail: options.requireVerifiedEmail ?? false,
  };

  if (config.emailVerification && !hooks.sendVerificationEmail) {
    throw new Error('createAuth: `emailVerification` needs a `sendVerificationEmail` hook');
  }
  if (!hooks.sendPasswordResetEmail) {
    console.warn('[auth] no sendPasswordResetEmail hook: forgot-password will not send anything');
  }

  const cleanupIntervalMs = options.tokenCleanupIntervalMs ?? HOUR;
  if (cleanupIntervalMs) {
    setInterval(() => {
      adapter.deleteExpiredTokens().catch((err) => console.error('[auth] token cleanup failed:', err));
    }, cleanupIntervalMs).unref();
  }

  const tokens = createTokenService({ adapter, config });
  const service = createAuthService({ adapter, tokens, config, hooks });
  const authenticate = createAuthenticate(tokens, config.checkTokenVersion ? adapter : null);
  const rateLimiter =
    options.rateLimiter === false || options.rateLimit === false
      ? null
      : options.rateLimiter ?? createRateLimiter(options.rateLimit);
  // Admin routes always check the database, so a removed admin loses access immediately.
  const adminGuard = [createAuthenticate(tokens, adapter), requireRoles(config.adminRole)];
  const router = createAuthRouter({ service, authenticate, adminGuard, rateLimiter });

  /** Mount in your app after your routes so `authenticate` errors return JSON. */
  // eslint-disable-next-line no-unused-vars
  const errorHandler = (err, _req, res, next) => {
    if (err instanceof AuthError) {
      return res.status(err.status).json({ error: { code: err.code, message: err.message } });
    }
    next(err);
  };

  return { router, authenticate, requireRoles, service, tokens, errorHandler };
}

export { AuthError, requireRoles, defaultPasswordPolicy, createRateLimiter };
export { memoryAdapter } from './adapters/memoryAdapter.js';
