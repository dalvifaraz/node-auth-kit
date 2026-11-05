import { hashPassword, verifyPassword } from '../utils/crypto.js';
import { normalizeEmail } from '../utils/validate.js';
import { Errors } from '../utils/errors.js';
import { TOKEN_TYPES } from './tokenService.js';

/** Strip sensitive fields before returning a user to the client. */
export const toPublicUser = (user) => {
  if (!user) return null;
  const { passwordHash, ...rest } = user;
  return { ...rest, id: String(user.id) };
};

export function createAuthService({ adapter, tokens, config, hooks }) {
  let dummyHash; // lazily created; used when the email doesn't exist
  const checkPassword = (password) => {
    const problem = config.passwordPolicy(password);
    if (problem) throw Errors.validation(problem);
  };

  async function register({ email, password, name, ...extra }) {
    const normalized = normalizeEmail(email);
    checkPassword(password);

    if (await adapter.findUserByEmail(normalized)) throw Errors.emailTaken();

    const user = await adapter.createUser({
      email: normalized,
      passwordHash: await hashPassword(password, config.bcryptRounds),
      name: name ?? null,
      roles: config.defaultRoles,
      emailVerified: false,
      ...pick(extra, config.allowedRegisterFields),
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    if (config.emailVerification) {
      const token = await tokens.issueOpaqueToken(user.id, TOKEN_TYPES.EMAIL_VERIFY, config.verifyTokenTtlMs);
      await hooks.sendVerificationEmail?.({ user: toPublicUser(user), token });
    }
    await hooks.onRegister?.(toPublicUser(user));

    return { user: toPublicUser(user), ...(await tokens.issueTokenPair(user)) };
  }

  async function login({ email, password }, meta = {}) {
    const normalized = normalizeEmail(email);
    const user = await adapter.findUserByEmail(normalized);
    // Always run bcrypt to keep response time constant (prevents user enumeration by timing).
    dummyHash ??= hashPassword('dummy-password-for-timing', config.bcryptRounds);
    const ok = await verifyPassword(
      typeof password === 'string' ? password : '',
      user?.passwordHash ?? (await dummyHash)
    );
    if (!user || !ok) throw Errors.invalidCredentials();
    if (config.emailVerification && config.requireVerifiedEmail && !user.emailVerified) {
      throw Errors.forbidden('Please verify your email before logging in');
    }
    await hooks.onLogin?.(toPublicUser(user), meta);
    return { user: toPublicUser(user), ...(await tokens.issueTokenPair(user, meta)) };
  }

  /** Refresh token rotation: the old token is consumed, a new pair issued. */
  async function refresh(refreshToken, meta = {}) {
    const record = await tokens.consumeOpaqueToken(refreshToken, TOKEN_TYPES.REFRESH);
    const user = await adapter.findUserById(record.userId);
    if (!user) throw Errors.invalidToken();
    return { user: toPublicUser(user), ...(await tokens.issueTokenPair(user, meta)) };
  }

  async function logout(refreshToken) {
    if (refreshToken) await tokens.revokeRefreshToken(refreshToken);
  }

  async function logoutAll(userId) {
    await tokens.revokeAllForUser(userId);
  }

  async function me(userId) {
    const user = await adapter.findUserById(userId);
    if (!user) throw Errors.notFound('User not found');
    return toPublicUser(user);
  }

  async function changePassword(userId, { currentPassword, newPassword }) {
    const user = await adapter.findUserById(userId);
    if (!user) throw Errors.notFound('User not found');
    if (!(await verifyPassword(currentPassword ?? '', user.passwordHash))) {
      throw Errors.invalidCredentials();
    }
    checkPassword(newPassword);
    await adapter.updateUser(user.id, {
      passwordHash: await hashPassword(newPassword, config.bcryptRounds),
      updatedAt: new Date(),
    });
    await tokens.revokeAllForUser(user.id); // sign out other sessions
  }

  /** Always resolves the same way so attackers can't discover registered emails. */
  async function forgotPassword({ email }) {
    const normalized = normalizeEmail(email);
    const user = await adapter.findUserByEmail(normalized);
    if (!user) return;
    await tokens.revokeAllForUser(user.id, TOKEN_TYPES.PASSWORD_RESET);
    const token = await tokens.issueOpaqueToken(user.id, TOKEN_TYPES.PASSWORD_RESET, config.resetTokenTtlMs);
    await hooks.sendPasswordResetEmail?.({ user: toPublicUser(user), token });
  }

  async function resetPassword({ token, newPassword }) {
    checkPassword(newPassword);
    const record = await tokens.consumeOpaqueToken(token, TOKEN_TYPES.PASSWORD_RESET);
    await adapter.updateUser(record.userId, {
      passwordHash: await hashPassword(newPassword, config.bcryptRounds),
      updatedAt: new Date(),
    });
    await tokens.revokeAllForUser(record.userId);
  }

  async function verifyEmail({ token }) {
    const record = await tokens.consumeOpaqueToken(token, TOKEN_TYPES.EMAIL_VERIFY);
    await adapter.updateUser(record.userId, { emailVerified: true, updatedAt: new Date() });
  }

  return {
    register, login, refresh, logout, logoutAll, me,
    changePassword, forgotPassword, resetPassword, verifyEmail,
  };
}

function pick(obj, keys = []) {
  return Object.fromEntries(keys.filter((k) => k in obj).map((k) => [k, obj[k]]));
}
