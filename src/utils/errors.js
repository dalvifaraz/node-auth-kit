export class AuthError extends Error {
  constructor(message, status = 400, code = 'AUTH_ERROR') {
    super(message);
    this.name = 'AuthError';
    this.status = status;
    this.code = code;
  }
}

export const Errors = {
  validation: (msg) => new AuthError(msg, 400, 'VALIDATION_ERROR'),
  emailTaken: () => new AuthError('Email is already registered', 409, 'EMAIL_TAKEN'),
  invalidCredentials: () => new AuthError('Invalid email or password', 401, 'INVALID_CREDENTIALS'),
  unauthorized: (msg = 'Unauthorized') => new AuthError(msg, 401, 'UNAUTHORIZED'),
  forbidden: (msg = 'Forbidden') => new AuthError(msg, 403, 'FORBIDDEN'),
  accountDisabled: () => new AuthError('This account has been disabled', 403, 'ACCOUNT_DISABLED'),
  invalidToken: (msg = 'Invalid or expired token') => new AuthError(msg, 401, 'INVALID_TOKEN'),
  notAvailable: (msg) => new AuthError(msg, 501, 'NOT_AVAILABLE'),
  tooManyRequests: (msg = 'Too many requests, try again later') => new AuthError(msg, 429, 'RATE_LIMITED'),
  identityTaken: () => new AuthError('This sign-in is already linked to an account', 409, 'IDENTITY_TAKEN'),
  emailNotVerified: () => new AuthError('The sign-in provider has not verified this email', 403, 'EMAIL_NOT_VERIFIED'),
  notFound: (msg = 'Not found') => new AuthError(msg, 404, 'NOT_FOUND'),
};
