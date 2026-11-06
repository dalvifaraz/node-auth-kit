import { Errors } from './errors.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function normalizeEmail(email) {
  if (typeof email !== 'string' || !EMAIL_RE.test(email.trim())) {
    throw Errors.validation('A valid email is required');
  }
  return email.trim().toLowerCase();
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
