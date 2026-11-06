import { hashPassword, verifyPassword, MAX_PASSWORD_BYTES } from '../utils/crypto.js';
import { normalizeEmail, checkName } from '../utils/validate.js';
import { Errors } from '../utils/errors.js';
import { TOKEN_TYPES } from './tokenService.js';

const PUBLIC_FIELDS = ['id', 'email', 'name', 'roles', 'emailVerified', 'disabled', 'createdAt', 'updatedAt'];
const PRIVATE_FIELDS = ['passwordHash', 'tokenVersion'];

const isTooLong = (password) => Buffer.byteLength(password) > MAX_PASSWORD_BYTES;

export function createAuthService({ adapter, tokens, config, hooks }) {
  let dummyHash; // lazily created; used when the email doesn't exist

  const publicFields = [...PUBLIC_FIELDS, ...config.allowedRegisterFields, ...config.publicUserFields]
    .filter((field) => !PRIVATE_FIELDS.includes(field));

  /** Only allowlisted fields ever reach the client. */
  const toPublicUser = (user) => (user ? { ...pick(user, publicFields), id: String(user.id) } : null);

  const checkPassword = (password) => {
    const problem = config.passwordPolicy(password);
    if (problem) throw Errors.validation(problem);
    if (typeof password !== 'string') throw Errors.validation('Password is required');
    if (isTooLong(password)) throw Errors.validation(`Password must be at most ${MAX_PASSWORD_BYTES} bytes`);
  };

  const assertCanSignIn = (user) => {
    if (user.disabled) throw Errors.accountDisabled();
    if (config.requireVerifiedEmail && !user.emailVerified) {
      throw Errors.forbidden('Please verify your email before logging in');
    }
  };

  /** A failing hook is logged, never allowed to break the request that triggered it. */
  const runHook = async (name, ...args) => {
    try {
      await hooks[name]?.(...args);
    } catch (err) {
      console.error(`[auth] ${name} hook failed:`, err);
    }
  };

  async function sendVerificationEmail(user) {
    const token = await tokens.issueOpaqueToken(user.id, TOKEN_TYPES.EMAIL_VERIFY, config.verifyTokenTtlMs);
    await runHook('sendVerificationEmail', { user: toPublicUser(user), token });
  }

  async function register({ email, password, name, ...extra }, meta = {}) {
    const normalized = normalizeEmail(email);
    checkPassword(password);
    checkName(name);

    if (await adapter.findUserByEmail(normalized)) throw Errors.emailTaken();

    const user = await adapter.createUser({
      email: normalized,
      passwordHash: await hashPassword(password, config.bcryptRounds),
      name: name ?? null,
      roles: [...config.defaultRoles],
      emailVerified: false,
      tokenVersion: 0,
      disabled: false,
      ...pick(extra, config.allowedRegisterFields),
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    if (config.emailVerification) await sendVerificationEmail(user);
    await runHook('onRegister', toPublicUser(user));

    if (config.requireVerifiedEmail) return { user: toPublicUser(user) };
    return { user: toPublicUser(user), ...(await tokens.issueTokenPair(user, meta)) };
  }

  async function login({ email, password }, meta = {}) {
    const normalized = normalizeEmail(email);
    const user = await adapter.findUserByEmail(normalized);
    // Always run bcrypt to keep response time constant (prevents user enumeration by timing).
    dummyHash ??= hashPassword('dummy-password-for-timing', config.bcryptRounds);
    const candidate = typeof password === 'string' ? password : '';
    const ok = await verifyPassword(candidate, user?.passwordHash ?? (await dummyHash));
    if (!user || !ok || isTooLong(candidate)) throw Errors.invalidCredentials();
    assertCanSignIn(user);
    await runHook('onLogin', toPublicUser(user), meta);
    return { user: toPublicUser(user), ...(await tokens.issueTokenPair(user, meta)) };
  }

  /** Refresh token rotation: the old token is consumed, a new pair issued. */
  async function refresh(refreshToken, meta = {}) {
    const record = await tokens.consumeRefreshToken(refreshToken, revokeSessions);
    const user = await adapter.findUserById(record.userId);
    if (!user) throw Errors.invalidToken();
    assertCanSignIn(user);
    return { user: toPublicUser(user), ...(await tokens.issueTokenPair(user, meta)) };
  }

  async function logout(refreshToken) {
    if (refreshToken && typeof refreshToken === 'string') await tokens.revokeRefreshToken(refreshToken);
  }

  /** Ends every session: refresh tokens are deleted and existing access tokens stop working. */
  async function revokeSessions(userId) {
    const user = await adapter.findUserById(userId);
    if (!user) return null;
    const tokenVersion = (user.tokenVersion ?? 0) + 1;
    await adapter.updateUser(user.id, { tokenVersion, updatedAt: new Date() });
    await tokens.revokeAllForUser(user.id);
    await tokens.revokeAllForUser(user.id, TOKEN_TYPES.REFRESH_USED);
    return { ...user, tokenVersion };
  }

  async function logoutAll(userId) {
    await revokeSessions(userId);
  }

  async function me(userId) {
    const user = await adapter.findUserById(userId);
    if (!user) throw Errors.notFound('User not found');
    return toPublicUser(user);
  }

  async function changePassword(userId, { currentPassword, newPassword }) {
    const user = await adapter.findUserById(userId);
    if (!user) throw Errors.notFound('User not found');
    const candidate = typeof currentPassword === 'string' ? currentPassword : '';
    if (!(await verifyPassword(candidate, user.passwordHash))) {
      throw Errors.invalidCredentials();
    }
    checkPassword(newPassword);
    await adapter.updateUser(user.id, {
      passwordHash: await hashPassword(newPassword, config.bcryptRounds),
      updatedAt: new Date(),
    });
    await tokens.revokeAllForUser(user.id, TOKEN_TYPES.PASSWORD_RESET);
    const updated = await revokeSessions(user.id);
    return { user: toPublicUser(updated), ...(await tokens.issueTokenPair(updated)) };
  }

  /** Runs after the response, so timing and failures can't reveal which emails are registered. */
  async function forgotPassword({ email }) {
    const normalized = normalizeEmail(email);
    sendResetEmail(normalized).catch((err) => console.error('[auth] password reset email failed:', err));
  }

  async function sendResetEmail(email) {
    const user = await adapter.findUserByEmail(email);
    if (!user || user.disabled) return;
    await tokens.revokeAllForUser(user.id, TOKEN_TYPES.PASSWORD_RESET);
    const token = await tokens.issueOpaqueToken(user.id, TOKEN_TYPES.PASSWORD_RESET, config.resetTokenTtlMs);
    await hooks.sendPasswordResetEmail?.({ user: toPublicUser(user), token });
  }

  async function resetPassword({ token, newPassword }) {
    checkPassword(newPassword);
    const record = await tokens.consumeOpaqueToken(token, TOKEN_TYPES.PASSWORD_RESET);
    await adapter.updateUser(record.userId, {
      passwordHash: await hashPassword(newPassword, config.bcryptRounds),
      emailVerified: true, // the reset link proves they own the address
      updatedAt: new Date(),
    });
    await revokeSessions(record.userId);
  }

  /** Runs after the response, like forgotPassword, so it can't reveal which emails are registered. */
  async function resendVerification({ email }) {
    const normalized = normalizeEmail(email);
    replaceVerificationEmail(normalized).catch((err) => console.error('[auth] verification email failed:', err));
  }

  async function replaceVerificationEmail(email) {
    if (!config.emailVerification) return;
    const user = await adapter.findUserByEmail(email);
    if (!user || user.disabled || user.emailVerified) return;
    await tokens.revokeAllForUser(user.id, TOKEN_TYPES.EMAIL_VERIFY);
    await sendVerificationEmail(user);
  }

  async function verifyEmail({ token }) {
    const record = await tokens.consumeOpaqueToken(token, TOKEN_TYPES.EMAIL_VERIFY);
    await adapter.updateUser(record.userId, { emailVerified: true, updatedAt: new Date() });
  }

  async function setDisabled(userId, disabled, { actorId } = {}) {
    if (disabled && String(userId) === String(actorId)) throw Errors.validation('You cannot disable your own account');
    const user = await adapter.findUserById(userId);
    if (!user) throw Errors.notFound('User not found');
    await adapter.updateUser(user.id, { disabled: Boolean(disabled), updatedAt: new Date() });
    if (disabled) await revokeSessions(user.id);
    return toPublicUser(await adapter.findUserById(user.id));
  }

  return {
    register, login, refresh, logout, logoutAll, me,
    changePassword, forgotPassword, resetPassword, verifyEmail, resendVerification,
    setDisabled,
  };
}

function pick(obj, keys = []) {
  return Object.fromEntries(keys.filter((k) => k in obj).map((k) => [k, obj[k]]));
}
