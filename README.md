# node-auth-kit

Reusable authentication for Node.js and Express. Install it in each project's backend, choose a database with one adapter, and every project gets the same login system with its own users.

- **Accounts:** register, login, logout, logout everywhere, change password, forgot and reset password, email verification, change email, delete account
- **Sign in with Google and GitHub**, or any other OAuth provider
- **Tokens:** short-lived JWT access tokens, plus rotating refresh tokens that are stored hashed and detect theft
- **Web and mobile:** refresh token in an httpOnly cookie for browsers, or in the response body for mobile and API clients
- **Email:** reset, verification and email-change messages over SMTP from environment variables, or your own hooks
- **Admin:** list and search users, assign roles, disable and delete accounts
- **Databases:** PostgreSQL and MongoDB, tested in CI against real servers, plus an in-memory adapter for tests

## How it fits together

```
            your app (Express 4 or 5)
                   │  app.use('/api/auth', auth.router)
┌──────────────────▼──────────────────┐
│ routes  →  authService  →  tokenSvc │   ← the same in every project
└──────────────────┬──────────────────┘
                   │  14-method adapter contract
     ┌─────────────┼──────────────┐
  memory        mongo          postgres   (or your own)
```

```
src/
  index.js                createAuth(), the only entry point
  services/               auth logic, tokens, email, sign-in providers
  middleware/             authenticate, requireRoles, rate limiter, session cookie
  routes/                 the Express router, and the provider sign-in routes
  adapters/               database adapters and their contract
  testing/                contract tests for any adapter
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
npm install github:dalvifaraz/node-auth-kit#v1.0.0 pg    # or mongodb instead of pg
```

Your project also needs Express 4.21 or newer, or Express 5.

```js
import express from 'express';
import pg from 'pg';
import { createAuth, emailConfigFromEnv, oauthConfigFromEnv } from 'node-auth-kit';
import { postgresAdapter } from 'node-auth-kit/adapters/postgres';

const adapter = postgresAdapter({ pool: new pg.Pool({ connectionString: process.env.DATABASE_URL }) });
await adapter.init(); // creates or updates the tables

const auth = createAuth({
  adapter,
  jwtSecret: process.env.JWT_SECRET,
  audience: 'my-project',
  email: emailConfigFromEnv(),
  oauth: oauthConfigFromEnv(),
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

Every project uses the same tables: `auth_users`, `auth_tokens` and `auth_identities` in Postgres, and `users`, `auth_tokens` and `auth_identities` in Mongo. To collect extra fields at signup, list them in `allowedRegisterFields`. They are stored alongside the user, with no schema change. `publicUserFields` adds other stored fields to API responses.

Call `adapter.init()` at startup. It's safe to run every time, and it adds any tables, columns or indexes a newer version needs.

To check a custom adapter, run the contract tests against it with `node --test`:

```js
import { runAdapterContract } from 'node-auth-kit/testing';
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

**Mobile and API clients** can use the same backend: send `"tokenDelivery": "body"` to `/login`, `/register` or `/oauth/exchange` to get the refresh token in the response, then send it in the body of `/refresh` and `/logout`. A request that used the cookie is always answered with the cookie, so page scripts can't extract the token.

## Sign in with Google and GitHub

### 1. Get keys from each provider

You need a client ID and client secret from each provider you want. Both are free. The **callback URL** is your API's address, plus where you mount the router, plus `/oauth/<provider>/callback`. For example:

- Live: `https://api.example.com/api/auth/oauth/google/callback`
- Local: `http://localhost:3000/api/auth/oauth/google/callback`

**Google**

1. Open the [Google Cloud console](https://console.cloud.google.com/) and create a project, or pick one.
2. Go to **Google Auth Platform**, also listed under **APIs & Services → OAuth consent screen**. Fill in the app name and support email, and choose **External** users.
3. Go to **Clients → Create client**, choose **Web application**, and add the callback URL under **Authorized redirect URIs**.
4. Copy the **Client ID** and **Client secret**.
5. While the app is in **Testing**, only test users you list can sign in. **Publish** it when you go live.

**GitHub**

1. Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**.
2. Fill in the app name and homepage URL, and put the callback URL under **Authorization callback URL**.
3. Select **Register application**, then **Generate a new client secret**.
4. Copy the **Client ID** and the secret. GitHub shows the secret only once.

Each OAuth app takes one callback URL, so create one for local development and one for live.

### 2. Configure

```bash
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
AUTH_PUBLIC_URL=https://api.example.com/api/auth    # where the router is mounted
OAUTH_REDIRECT_URL=https://app.example.com/signed-in   # your frontend page
```

```js
createAuth({ /* ... */ oauth: oauthConfigFromEnv() });
```

`oauthConfigFromEnv()` returns `null` when no client ID is set, which leaves provider sign-in off. For local HTTP development, also set `OAUTH_COOKIE_SECURE=false`.

### 3. Frontend

1. A "Sign in with Google" button is a plain link to `/api/auth/oauth/google`.
2. After the provider, the browser lands on your redirect page with `?code=...`, or `?error=...` if something failed.
3. The page posts the code to `/api/auth/oauth/exchange`, which returns a normal session, the same as `/login`.

```js
const code = new URLSearchParams(location.search).get('code');
const res = await fetch('/api/auth/oauth/exchange', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({ code }),
});
```

The code works once, within 60 seconds. The possible errors are `access_denied`, `email_not_verified`, `account_disabled`, `invalid_state` and `oauth_failed`.

To return to a different page, such as a mobile app link, list every allowed address in `redirectUrl` and add `?redirect=<address>` to the sign-in link.

### How accounts are matched

- Only email addresses the provider has verified are accepted.
- The same Google or GitHub account always returns to the same user, even if they change their email at the provider.
- A first sign-in links to an existing account with the same email. If that account was never verified, its password and sessions are removed first, because whoever registered it never proved they own the address.
- Accounts created this way have no password, and `hasPassword` is `false`. They can set one through forgot-password.
- An account without a password must set one before changing its email, and must type its email address to delete itself.

| `oauth` option | | |
| --- | --- | --- |
| `publicUrl` | **required** | the full URL where the router is mounted |
| `redirectUrl` | **required** | frontend page, or a list of allowed ones; the first is the default |
| `providers` | **required** | `{ google: { clientId, clientSecret }, github: { ... } }` |
| `cookieSecure` | `true` | `false` only for local HTTP development |

For another provider, give `authorizeUrl`, `tokenUrl`, `scope` and `getProfile(accessToken, fetchJson)`, which must return `{ id, email, emailVerified, name }`.

## Email

With SMTP settings, every email needs no code:

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

Links point to your frontend, which reads `token` from the address and posts it to the matching API route:

| Email | Link | Frontend posts to |
| --- | --- | --- |
| Password reset | `APP_URL/reset-password?token=...` | `/reset-password` with the new password |
| Verify email | `APP_URL/verify-email?token=...` | `/verify-email` |
| Confirm new email | `APP_URL/confirm-email-change?token=...` | `/confirm-email-change` |

After an email change, the old address also gets a notice.

| `email` option | Default | |
| --- | --- | --- |
| `smtp` | | SMTP URL or nodemailer options |
| `transport` | | anything with `sendMail()`, used instead of `smtp` |
| `from` | **required** | sender |
| `appUrl` | **required** | your frontend's address |
| `appName` | `Your app` | used in the emails |
| `resetPath` / `verifyPath` / `changeEmailPath` | `/reset-password` / `/verify-email` / `/confirm-email-change` | frontend pages for the links |
| `templates` | built in | `{ passwordReset, verifyEmail, emailChange, emailChanged }`: functions taking `{ user, link, appName, expiresIn, newEmail }` and returning `{ subject, text, html }` |

To send email another way, pass hooks: `sendPasswordResetEmail`, `sendVerificationEmail`, `sendEmailChangeEmail` and `sendEmailChangedNotice`. A hook replaces the built-in email of the same kind. Without `sendEmailChangeEmail`, `/change-email` answers 501.

Each account gets at most one email of each kind per `emailCooldownMs`. The cooldown is held per process.

## Admin and roles

Users with the admin role can use the `/admin/users` routes. Create the first admin from a setup script, or at startup, once that person has registered:

```js
await auth.service.addRoleByEmail('you@example.com', 'admin');
```

Admins can't remove their own admin role, disable themselves or delete themselves, so a project can't lock itself out. Disabling an account ends all of its sessions at once.

## Deleting accounts

Users delete their own account with `DELETE /me`, after confirming their password. Admins can delete other accounts. The user, their tokens and their linked sign-ins are all removed. To delete your app's own data for that user, use the `onUserDeleted` hook:

```js
hooks: { onUserDeleted: async (user) => { await db.orders.deleteMany({ userId: user.id }); } }
```

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
| DELETE | `/me` | `{ password }`, or `{ confirmEmail }` without a password | Bearer |
| POST | `/change-password` | `{ currentPassword, newPassword }` | Bearer |
| POST | `/change-email` | `{ password, newEmail }` | Bearer |
| POST | `/confirm-email-change` | `{ token }` | none |
| POST | `/forgot-password` | `{ email }` | none |
| POST | `/reset-password` | `{ token, newPassword }` | none |
| POST | `/verify-email` | `{ token }` | none |
| POST | `/resend-verification` | `{ email }` | none |
| GET | `/oauth/:provider?redirect=` | none | none |
| GET | `/oauth/:provider/callback` | called by the provider | none |
| POST | `/oauth/exchange` | `{ code, tokenDelivery? }` | none |
| GET | `/admin/users?limit=&offset=&search=` | none | Admin |
| GET | `/admin/users/:id` | none | Admin |
| PUT | `/admin/users/:id/roles` | `{ roles }` | Admin |
| POST | `/admin/users/:id/disable` | none | Admin |
| POST | `/admin/users/:id/enable` | none | Admin |
| DELETE | `/admin/users/:id` | none | Admin |

- `/register`, `/login`, `/refresh`, `/change-password` and `/oauth/exchange` return `{ user, accessToken, refreshToken, tokenType, expiresIn }`.
- In cookie mode, `refreshToken` is in the cookie instead.
- With `requireVerifiedEmail`, `/register` returns only `{ user }`.
- `/change-password` keeps the caller signed in with new tokens and ends every other session.
- Confirming an email change ends every session, so the user signs in again with the new address.
- `/admin/users` returns `{ users, total, limit, offset }`. `limit` is 20 by default and 100 at most. `search` matches part of the email.
- Users include `hasPassword`, but never the password hash.
- Errors are always `{ error: { code, message } }`.

## Options

| Option | Default | |
| --- | --- | --- |
| `adapter` | **required** | database adapter |
| `jwtSecret` | **required** | at least 32 characters, different per project |
| `previousJwtSecrets` | `[]` | old secrets still accepted while rotating, see below |
| `audience` / `issuer` | `node-auth-kit` | set `audience` per project |
| `accessTokenTtl` | `'15m'` | any `jsonwebtoken` duration |
| `refreshTokenTtlMs` | 30 days | |
| `refreshReuseGraceMs` | 10 seconds | replaying a used refresh token after this long ends all of the user's sessions |
| `resetTokenTtlMs` | 1 hour | |
| `verifyTokenTtlMs` | 2 days | also used for email change links |
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
| `emailCooldownMs` | 60 seconds | minimum gap between emails of one kind to one account |
| `email` | off | built-in email, see [Email](#email) |
| `oauth` | off | provider sign-in, see [Sign in with Google and GitHub](#sign-in-with-google-and-github) |
| `cookie` | off | cookie login, see [Browser apps](#browser-apps-cookie-login) |
| `rateLimit` | 10 requests per 15 minutes | `{ max, windowMs }` per IP and route, or `false` to turn it off |
| `rateLimiter` | built in | your own middleware, or `false` |
| `hooks` | `{}` | email hooks above, plus `onRegister`, `onLogin` and `onUserDeleted` |

`createAuth()` returns `{ router, authenticate, requireRoles, service, tokens, errorHandler }`.

### Changing JWT_SECRET

Refresh tokens don't depend on the secret, so changing it logs nobody out. To avoid a burst of failed requests while every access token is renewed:

1. Set the new secret as `jwtSecret`, and put the old one in `previousJwtSecrets`.
2. After `accessTokenTtl`, 15 minutes by default, remove the old secret.

## Security notes

- Keep `JWT_SECRET` and the provider secrets out of git. `.env` is already ignored.
- Serve everything over HTTPS.
- Rate limits go by client IP. Set Express `trust proxy` only when a proxy really is in front of the app, because otherwise clients can fake their IP.
- The built-in rate limiter and email cooldown are per process. With several instances, pass a shared limiter such as a Redis one.
- Login and forgot-password don't reveal whether an email is registered. `/register` and `/change-email` do return 409 for a taken email, and the rate limit slows bulk checks.
- A failing hook is logged and never fails the request, so hooks can't be used to block a login.
- Reset and verification emails are sent after the response, and failures are logged rather than returned. Platforms that freeze the process after responding, such as some serverless hosts, may need a queue.

## License

MIT
