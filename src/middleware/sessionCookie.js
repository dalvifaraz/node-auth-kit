import { Errors } from '../utils/errors.js';

const SAME_SITE_VALUES = ['strict', 'lax', 'none'];

function parseCookies(header = '') {
  const cookies = {};
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    const name = part.slice(0, index).trim();
    try {
      cookies[name] = decodeURIComponent(part.slice(index + 1).trim());
    } catch {
      // A malformed value is treated as if the cookie were absent.
    }
  }
  return cookies;
}

/**
 * Keeps the refresh token in an httpOnly cookie, out of reach of page scripts.
 * Returns null when cookie login is off. `options` is true or:
 *   { name, secure, sameSite, domain, path, allowedOrigins }
 */
export function createSessionCookie(options, maxAge) {
  if (!options) return null;
  const {
    name = 'auth_refresh',
    secure = true,
    sameSite = 'strict',
    domain,
    path,
    allowedOrigins = [],
  } = options === true ? {} : options;

  if (!SAME_SITE_VALUES.includes(sameSite)) {
    throw new Error(`createAuth: \`cookie.sameSite\` must be one of: ${SAME_SITE_VALUES.join(', ')}`);
  }
  if (sameSite === 'none' && (!secure || !allowedOrigins.length)) {
    throw new Error('createAuth: `cookie.sameSite: none` needs `secure` and `allowedOrigins`');
  }

  const attributes = (req) => ({ httpOnly: true, secure, sameSite, domain, path: path ?? (req.baseUrl || '/') });

  return {
    read: (req) => parseCookies(req.headers.cookie)[name],
    set: (req, res, token) => res.cookie(name, token, { ...attributes(req), maxAge }),
    clear: (req, res) => res.clearCookie(name, attributes(req)),
    /** Stops another site from using the cookie. Requests without an Origin header are not from a page. */
    assertOrigin(req) {
      const origin = req.get('origin');
      if (allowedOrigins.length && origin && !allowedOrigins.includes(origin)) {
        throw Errors.forbidden('Origin not allowed');
      }
    },
  };
}
