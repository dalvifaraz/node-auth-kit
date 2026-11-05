import { createTokenService } from './services/tokenService.js';
import { createAuthService } from './services/authService.js';
import { createAuthenticate, requireRoles } from './middleware/authenticate.js';
import { createRateLimiter } from './middleware/rateLimit.js';
import { createAuthRouter } from './routes/authRoutes.js';
import { defaultPasswordPolicy } from './utils/validate.js';
import { AuthError } from './utils/errors.js';

const REQUIRED_ADAPTER_METHODS = [
  'createUser', 'findUserByEmail', 'findUserById', 'updateUser',
  'saveToken', 'findToken', 'deleteToken', 'deleteUserTokens',
];

const DAY = 24 * 60 * 60 * 1000;

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

  const config = {
    jwtSecret: options.jwtSecret,
    accessTokenTtl: options.accessTokenTtl ?? '15m',
    refreshTokenTtlMs: options.refreshTokenTtlMs ?? 30 * DAY,
    resetTokenTtlMs: options.resetTokenTtlMs ?? 60 * 60 * 1000,
    verifyTokenTtlMs: options.verifyTokenTtlMs ?? 2 * DAY,
    issuer: options.issuer ?? 'node-auth-kit',
    audience: options.audience ?? 'node-auth-kit',
    bcryptRounds: options.bcryptRounds ?? 12,
    defaultRoles: options.defaultRoles ?? ['user'],
    allowedRegisterFields: options.allowedRegisterFields ?? [], // extra fields accepted on /register
    passwordPolicy: options.passwordPolicy ?? defaultPasswordPolicy,
    emailVerification: options.emailVerification ?? false,
    requireVerifiedEmail: options.requireVerifiedEmail ?? false,
  };

  const tokens = createTokenService({ adapter, config });
  const service = createAuthService({ adapter, tokens, config, hooks });
  const authenticate = createAuthenticate(tokens);
  const rateLimiter =
    options.rateLimiter === false ? null : options.rateLimiter ?? createRateLimiter(options.rateLimit);
  const router = createAuthRouter({ service, authenticate, rateLimiter });

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
