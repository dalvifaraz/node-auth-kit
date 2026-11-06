# Database adapters

The auth core never talks to a database directly. It only calls the methods below.
To use a new database (MySQL, SQLite, Prisma, DynamoDB, Firestore…), write an object
that implements these 8 async methods and pass it to `createAuth({ adapter })`.

| Method | Receives | Returns |
| --- | --- | --- |
| `createUser(data)` | `{ email, passwordHash, name, roles, emailVerified, createdAt, updatedAt, ...extra }` | created user **with `id`** |
| `findUserByEmail(email)` | lower-cased email | user or `null` |
| `findUserById(id)` | string id | user or `null` |
| `updateUser(id, fields)` | id, partial fields | updated user (or nothing) |
| `saveToken(record)` | `{ userId, tokenHash, type, expiresAt, meta }` | anything |
| `findToken(tokenHash, type)` | hash, type | record or `null` |
| `deleteToken(tokenHash)` | hash | anything |
| `deleteUserTokens(userId, type)` | id, type | anything |

Rules:
- `email` must be unique (add a unique index). On a duplicate, `createUser` must throw `Errors.emailTaken()`.
- Lookups by an id that is malformed for your database must return `null`, not throw.
- Users must expose `id` (string-able). Mongo's `_id` is mapped to `id` in `mongoAdapter.js`.
- `tokenHash` should be indexed/unique. Expired tokens can be cleaned up by a TTL index or a cron job.
- Optional: `init()` — create tables/indexes. Called by you, not by the core.

Use `tests/adapterContract.js` to test your own adapter against the same suite.
