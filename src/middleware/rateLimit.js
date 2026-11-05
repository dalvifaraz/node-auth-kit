import { AuthError } from '../utils/errors.js';

/**
 * Tiny in-memory fixed-window rate limiter for sensitive routes (login, forgot-password).
 * Fine for a single instance. Behind a load balancer, swap for a Redis-backed limiter
 * (e.g. express-rate-limit + rate-limit-redis) via createAuth({ rateLimiter }).
 */
export function createRateLimiter({ windowMs = 15 * 60 * 1000, max = 10 } = {}) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
  }, windowMs).unref();

  return function rateLimit(req, res, next) {
    const key = `${req.ip}:${req.baseUrl}${req.path}`;
    const now = Date.now();
    const entry = hits.get(key);
    if (!entry || entry.reset < now) {
      hits.set(key, { count: 1, reset: now + windowMs });
      return next();
    }
    if (++entry.count > max) {
      res.setHeader('Retry-After', Math.ceil((entry.reset - now) / 1000));
      return next(new AuthError('Too many requests, try again later', 429, 'RATE_LIMITED'));
    }
    next();
  };
}
