# node-auth-kit

Reusable authentication for Node.js and Express. Install it in each project's backend, choose a database with one adapter, and every project gets the same login system with its own users.

- **Accounts:** register, login, logout, logout everywhere, change password, forgot and reset password, email verification
- **Tokens:** short-lived JWT access tokens, plus rotating refresh tokens that are stored hashed and detect theft
- **Web and mobile:** refresh token in an httpOnly cookie for browsers, or in the response body for mobile and API clients
- **Email:** reset and verification emails over SMTP from environment variables, or your own hooks
- **Admin:** list and search users, assign roles, disable accounts
- **Databases:** PostgreSQL and MongoDB, tested in CI against real servers, plus an in-memory adapter for tests

## How it fits together

```
            your app (Express)
                   │  app.use('/api/auth', auth.router)
┌──────────────────▼──────────────────┐
│ routes  →  authService  →  tokenSvc │   ← the same in every project
└──────────────────┬──────────────────┘
                   │  11-method adapter contract
     ┌─────────────┼──────────────┐
  memory        mongo          postgres   (or your own)
```

```
src/
  index.js                createAuth(), the only entry point
  services/               auth logic, tokens, built-in email
  middleware/             authenticate, requireRoles, rate limiter, session cookie
  routes/authRoutes.js    Express router
  adapters/               database adapters and their contract
  utils/                  crypto, validation, errors
examples/server.js        runnable demo, configured through .env
tests/                    API tests, and adapter tests for every database
```

## Try it

```bash
npm install
cp .env.example .env
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

Paste the printed value into `.env` as `JWT_SECRET`. The app refuses to start with the placeholder. Then:

```bash
npm start     # http://localhost:3000, in-memory database
npm test
```

`npm test` skips the database tests unless `DATABASE_URL` and `MONGO_URL` are set. CI sets both.

## Use it in a project

```bash
npm install github:dalvifaraz/node-auth-kit pg    # or mongodb instead of pg
```

```js
import express from 'express';
import pg from 'pg';
import { createAuth, emailConfigFromEnv } from 'node-auth-kit';
import { postgresAdapter } from 'node-auth-kit/adapters/postgres';

const adapter = postgresAdapter({ pool: new pg.Pool({ connectionString: process.env.DATABASE_URL }) });
await adapter.init(); // creates or updates the tables

const auth = createAuth({
  adapter,
  jwtSecret: process.env.JWT_SECRET,
  audience: 'my-project',
  email: emailConfigFromEnv(),
});

const app = express();
app.use('/api/auth', auth.router);

// Protect your own routes
app.get('/api/orders', auth.authenticate, (req, res) => res.json({ user: req.auth.userId }));
app.get('/api/reports', auth.authenticate, auth.requireRoles('manager'), (req, res) => res.json({ ok: true }));

app.use(auth.errorHandler); // after your routes, so auth errors return JSON
```

**Each project needs its own `JWT_SECRET` and `audience`.** A token from one project is then useless in another.

### Choosing a database

| Database | Install | Adapter |
| --- | --- | --- |
| PostgreSQL 13+ | `npm i pg` | `postgresAdapter({ pool })` |
| MongoDB | `npm i mongodb` | `mongoAdapter({ db })` |
| In-memory (tests and demos) | none | `memoryAdapter()` |
| Anything else | your driver | implement the methods in [`src/adapters/README.md`](src/adapters/README.md) |

Every project uses the same tables: `auth_users` and `auth_tokens` in Postgres, `users` and `auth_tokens` in Mongo. To collect extra fields at signup, list them in `allowedRegisterFields`. They are stored alongside the user, with no schema change. `publicUserFields` adds other stored fields to API responses.

Call `adapter.init()` at startup. It's safe to run every time, and it adds any columns or indexes a newer version needs.

To check a custom adapter, run `tests/adapterContract.js` against it:

```js
runAdapterContract('mysql', () => mysqlAdapter({ pool }));
```

## Browser apps: cookie login

Turn this on for web frontends:

```js
createAuth({ /* ... */ cookie: true });
```

The refresh token then goes in an httpOnly cookie that page scripts can't read, so an XSS bug can't steal a long-lived login. The access token still arrives in the response body: keep it in memory, not in `localStorage`. After a page reload, call `/refresh` to get a new one.

```js
const res = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include' });
const { accessToken } = await res.json();
```

The cookie is sent only to the auth routes, and only over HTTPS. For local HTTP development, use `cookie: { secure: false }`.

| `cookie` option | Default | |
| --- | --- | --- |
| `name` | `auth_refresh` | |
| `secure` | `true` | HTTPS only |
| `sameSite` | `'strict'` | `strict`, `lax` or `none` |
| `domain` | none | set to share across subdomains |
| `path` | where the router is mounted | |
| `allowedOrigins` | `[]` | sites allowed to use the cookie; required with `sameSite: 'none'` |

If the frontend is on a different site from the API, use `sameSite: 'none'` with `allowedOrigins`, and enable CORS with credentials in your app.

**Mobile and API clients** can use the same backend: send `"tokenDelivery": "body"` to `/login` or `/register` to get the refresh token in the response, then send it in the body of `/refresh` and `/logout`. A request that used the cookie is always answered with the cookie, so page scripts can't extract the token.

## Email

With SMTP settings, reset and verification emails need no code:

```bash
SMTP_URL=smtps://user:password@smtp.example.com:465
EMAIL_FROM="My App <no-reply@example.com>"
APP_URL=https://app.example.com
APP_NAME=My App
```

```js
createAuth({ /* ... */ email: emailConfigFromEnv() });
```

`emailConfigFromEnv()` returns `null` when `SMTP_URL` isn't set, which leaves built-in email off.

Links point to your frontend: `APP_URL/reset-password?token=...` and `APP_URL/verify-email?token=...`. That page reads the token and posts it to `/reset-password` or `/verify-email`.

| `email` option | Default | |
| --- | --- | --- |
| `smtp` | | SMTP URL or nodemailer options |
| `transport` | | anything with `sendMail()`, used instead of `smtp` |
| `from` | **required** | sender |
| `appUrl` | **required** | your frontend's address |
| `appName` | `Your app` | used in the emails |
| `resetPath` / `verifyPath` | `/reset-password` / `/verify-email` | frontend pages for the links |
| `templates` | built in | `{ passwordReset, verifyEmail }`: functions taking `{ user, link, appName, expiresIn }` and returning `{ subject, text, html }` |

To send email another way, pass `sendPasswordResetEmail` or `sendVerificationEmail` in `hooks`. A hook replaces the built-in email of the same kind.

Each account gets at most one reset email and one verification email per `emailCooldownMs`. The cooldown is held per process.

## Admin and roles

Users with the admin role can use the `/admin/users` routes. Create the first admin from a setup script, or at startup, once that person has registered:

```js
await auth.service.addRoleByEmail('you@example.com', 'admin');
```

Admins can't remove their own admin role or disable themselves, so a project can't lock itself out. Disabling an account ends all of its sessions at once.

## API

Paths are relative to where you mount the router.

| Method | Path | Body | Auth |
| --- | --- | --- | --- |
| POST | `/register` | `{ email, password, name?, tokenDelivery? }` | none |
| POST | `/login` | `{ email, password, tokenDelivery? }` | none |
| POST | `/refresh` | `{ refreshToken }`, or the cookie | none |
| POST | `/logout` | `{ refreshToken }`, or the cookie | none |
| POST | `/logout-all` | none | Bearer |
| GET | `/me` | none | Bearer |
| POST | `/change-password` | `{ currentPassword, newPassword }` | Bearer |
| POST | `/forgot-password` | `{ email }` | none |
| POST | `/reset-password` | `{ token, newPassword }` | none |
| POST | `/verify-email` | `{ token }` | none |
| POST | `/resend-verification` | `{ email }` | none |
| GET | `/admin/users?limit=&offset=&search=` | none | Admin |
| GET | `/admin/users/:id` | none | Admin |
| PUT | `/admin/users/:id/roles` | `{ roles }` | Admin |
| POST | `/admin/users/:id/disable` | none | Admin |
| POST | `/admin/users/:id/enable` | none | Admin |

- `/register`, `/login`, `/refresh` and `/change-password` return `{ user, accessToken, refreshToken, tokenType, expiresIn }`.
- In cookie mode, `refreshToken` is in the cookie instead.
- With `requireVerifiedEmail`, `/register` returns only `{ user }`.
- `/change-password` keeps the caller signed in with new tokens and ends every other session.
- `/admin/users` returns `{ users, total, limit, offset }`. `limit` is 20 by default and 100 at most. `search` matches part of the email.
- Errors are always `{ error: { code, message } }`.

## Options

| Option | Default | |
| --- | --- | --- |
| `adapter` | **required** | database adapter |
| `jwtSecret` | **required** | at least 32 characters, different per project |
| `audience` / `issuer` | `node-auth-kit` | set `audience` per project |
| `accessTokenTtl` | `'15m'` | any `jsonwebtoken` duration |
| `refreshTokenTtlMs` | 30 days | |
| `refreshReuseGraceMs` | 10 seconds | replaying a used refresh token after this long ends all of the user's sessions |
| `resetTokenTtlMs` | 1 hour | |
| `verifyTokenTtlMs` | 2 days | |
| `tokenCleanupIntervalMs` | 1 hour | how often expired tokens are deleted; `false` to schedule `adapter.deleteExpiredTokens()` yourself |
| `checkTokenVersion` | `true` | check each access token against the database, so revocation and role changes apply at once; `false` skips that lookup, and tokens then stay valid until they expire |
| `bcryptRounds` | `12` | |
| `defaultRoles` | `['user']` | |
| `adminRole` | `'admin'` | role that can use the admin routes |
| `allowedRegisterFields` | `[]` | extra fields accepted at signup, such as `['phone']`; protected fields like `roles` are refused |
| `publicUserFields` | `[]` | extra user fields returned to clients; everything else stays private |
| `passwordPolicy` | 8+ chars, letter and number | `(password) => errorMessage \| null`; 72 bytes is always the maximum |
| `emailVerification` | `false` | send a verification email at signup |
| `requireVerifiedEmail` | `false` | also give no tokens until verified; turns `emailVerification` on |
| `emailCooldownMs` | 60 seconds | minimum gap between reset or verification emails to one account |
| `email` | off | built-in email, see [Email](#email) |
| `cookie` | off | cookie login, see [Browser apps](#browser-apps-cookie-login) |
| `rateLimit` | 10 requests per 15 minutes | `{ max, windowMs }` per IP and route, or `false` to turn it off |
| `rateLimiter` | built in | your own middleware, or `false` |
| `hooks` | `{}` | `sendPasswordResetEmail`, `sendVerificationEmail`, `onRegister`, `onLogin` |

`createAuth()` returns `{ router, authenticate, requireRoles, service, tokens, errorHandler }`.

## Security notes

- Keep `JWT_SECRET` out of git. `.env` is already ignored.
- Serve everything over HTTPS.
- Rate limits go by client IP. Set Express `trust proxy` only when a proxy really is in front of the app, because otherwise clients can fake their IP.
- The built-in rate limiter and email cooldown are per process. With several instances, pass a shared limiter such as a Redis one.
- Login and forgot-password don't reveal whether an email is registered. `/register` does return 409 for a taken email, and the rate limit slows bulk checks.
- A failing hook is logged and never fails the request, so hooks can't be used to block a login.
- Reset emails are sent after the response, and failures are logged rather than returned. Platforms that freeze the process after responding, such as some serverless hosts, may need a queue.

## License

MIT
