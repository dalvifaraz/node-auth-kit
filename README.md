# node-auth-kit

A reusable, **database-agnostic** authentication module for Node.js + Express.
Write it once, drop it into every new project, and switch the database by swapping one adapter.

- Register / login / logout / logout-all / `me`
- JWT access tokens (short-lived) + **rotating opaque refresh tokens** (stored hashed, with stolen-token detection)
- Forgot / reset password, change password, optional email verification
- `authenticate` and `requireRoles()` middleware for your own routes
- bcrypt password hashing, built-in rate limiting; login and forgot-password do not reveal whether an email is registered
- Adapters included: **in-memory**, **MongoDB**, **PostgreSQL** — add any other DB in ~60 lines

## Architecture

```
            your app (Express)
                   │  app.use('/api/auth', auth.router)
┌──────────────────▼──────────────────┐
│ routes  →  authService  →  tokenSvc │   ← never changes between projects
└──────────────────┬──────────────────┘
                   │  10-method adapter contract
     ┌─────────────┼──────────────┐
  memory        mongo          postgres   (or your own: MySQL, Prisma, DynamoDB…)
```

```
src/
  index.js               createAuth() — the only entry point
  services/              business logic (auth + tokens)
  middleware/            authenticate, requireRoles, rate limiter
  routes/authRoutes.js   Express router
  adapters/              DB adapters + contract docs
  utils/                 crypto, validation, errors
examples/server.js       runnable demo (DB chosen via .env)
tests/                   API tests + reusable adapter contract tests
```

## Quick start

```bash
npm install
cp .env.example .env        # set JWT_SECRET
npm start                   # http://localhost:3000, in-memory DB
npm test
```

## Use it in a new project

```js
import express from 'express';
import { createAuth } from 'node-auth-kit';
import { postgresAdapter } from 'node-auth-kit/adapters/postgres';
import pg from 'pg';

const adapter = postgresAdapter({ pool: new pg.Pool({ connectionString: process.env.DATABASE_URL }) });
await adapter.init();

const auth = createAuth({
  adapter,
  jwtSecret: process.env.JWT_SECRET,
  hooks: {
    sendPasswordResetEmail: async ({ user, token }) => { /* send email */ },
  },
});

const app = express();
app.use('/api/auth', auth.router);
app.get('/api/orders', auth.authenticate, (req, res) => res.json({ user: req.auth.userId }));
app.use(auth.errorHandler);
```

Install straight from GitHub in any project (no npm publishing needed):

```bash
npm install github:<your-username>/node-auth-kit#v1.0.0
```

### Switching databases

| DB | Install | Adapter |
| --- | --- | --- |
| In-memory (tests) | — | `memoryAdapter()` |
| MongoDB | `npm i mongodb` | `mongoAdapter({ db })` |
| PostgreSQL | `npm i pg` | `postgresAdapter({ pool })` |
| Anything else | your driver | implement the 10 methods in [`src/adapters/README.md`](src/adapters/README.md) |

Then prove your adapter works with the shared contract tests:

```js
import { runAdapterContract } from './tests/adapterContract.js';
runAdapterContract('mysql', () => mysqlAdapter({ pool }));
```

## API

| Method | Path | Body | Auth |
| --- | --- | --- | --- |
| POST | `/register` | `{ email, password, name? }` | — |
| POST | `/login` | `{ email, password }` | — |
| POST | `/refresh` | `{ refreshToken }` | — |
| POST | `/logout` | `{ refreshToken }` | — |
| POST | `/logout-all` | — | Bearer |
| GET | `/me` | — | Bearer |
| POST | `/change-password` | `{ currentPassword, newPassword }` (returns new tokens) | Bearer |
| POST | `/forgot-password` | `{ email }` | — |
| POST | `/reset-password` | `{ token, newPassword }` | — |
| POST | `/verify-email` | `{ token }` | — |
| POST | `/resend-verification` | `{ email }` | — |

Login/register/refresh return `{ user, accessToken, refreshToken, tokenType, expiresIn }`.
With `requireVerifiedEmail`, register returns only `{ user }`.
Errors are always `{ error: { code, message } }`.

## Options

| Option | Default | |
| --- | --- | --- |
| `adapter` | **required** | DB adapter |
| `jwtSecret` | **required** | ≥ 32 chars |
| `accessTokenTtl` | `'15m'` | any `jsonwebtoken` duration |
| `refreshTokenTtlMs` | 30 days | |
| `refreshReuseGraceMs` | 10 seconds | replaying a used refresh token after this long ends all of the user's sessions |
| `resetTokenTtlMs` | 1 hour | |
| `tokenCleanupIntervalMs` | 1 hour | how often expired tokens are deleted; `false` to schedule `adapter.deleteExpiredTokens()` yourself |
| `bcryptRounds` | `12` | |
| `checkTokenVersion` | `true` | check each access token against the database, so revocation and role changes apply at once; `false` skips that lookup, and access tokens then stay valid until they expire |
| `defaultRoles` | `['user']` | |
| `allowedRegisterFields` | `[]` | extra fields accepted at register (e.g. `['phone']`) |
| `publicUserFields` | `[]` | extra user fields returned to clients; everything else stays private |
| `passwordPolicy` | 8+ chars, letter + number | `(pw) => errorMessage \| null` |
| `emailVerification` | `false` | send a verification email at register |
| `requireVerifiedEmail` | `false` | also block tokens until verified; turns `emailVerification` on |
| `rateLimit` / `rateLimiter` | 10 req / 15 min | pass `false` to disable or your own middleware |
| `hooks` | `{}` | `sendPasswordResetEmail`, `sendVerificationEmail`, `onRegister`, `onLogin` |

## Security notes

- Keep `JWT_SECRET` out of git (`.env` is ignored). Use a different secret per project.
- `/register` does return 409 for a taken email, so it can show that an account exists. The rate limit slows bulk checks.
- A failing hook is logged and never fails the request, so hooks cannot be used to block a login.
- `sendPasswordResetEmail` runs after the response is sent, so failures are logged rather than returned. Platforms that freeze the process after responding, such as some serverless hosts, may need a queue.
- Serve over HTTPS. On the frontend, keep the access token in memory; store the refresh token in an httpOnly cookie or secure storage.
- The built-in rate limiter is per-process. Behind multiple instances, pass a Redis-backed limiter.
- Rate limits go by client IP. Set Express `trust proxy` only when a proxy is really in front of the app, because otherwise clients can fake their IP.

## Roadmap ideas

OAuth (Google/GitHub), 2FA (TOTP), httpOnly cookie mode, account lockout, audit log, TypeScript types.

## License

MIT
