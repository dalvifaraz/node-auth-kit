import { Errors } from './errors.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EMAIL_LENGTH = 254;
const MAX_NAME_LENGTH = 100;

export function normalizeEmail(email) {
  if (typeof email !== 'string' || email.length > MAX_EMAIL_LENGTH || !EMAIL_RE.test(email.trim())) {
    throw Errors.validation('A valid email is required');
  }
  return email.trim().toLowerCase();
}

/** A name is optional, but must be a reasonably short string when given. */
export function checkName(name) {
  if (name === undefined || name === null) return;
  if (typeof name !== 'string' || name.length > MAX_NAME_LENGTH) {
    throw Errors.validation(`Name must be text of at most ${MAX_NAME_LENGTH} characters`);
  }
}

/**
 * Default password policy. Override via createAuth({ passwordPolicy }).
 * Return null if OK, or an error message string.
 */
export function defaultPasswordPolicy(password) {
  if (typeof password !== 'string') return 'Password is required';
  if (password.length < 8) return 'Password must be at least 8 characters';
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    return 'Password must contain at least one letter and one number';
  }
  return null;
}
