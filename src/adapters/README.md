# Database adapters

The auth core never talks to a database directly. It only calls the methods below.
To use a new database (MySQL, SQLite, Prisma, DynamoDB, Firestore…), write an object
that implements these 14 async methods and pass it to `createAuth({ adapter })`.

| Method | Receives | Returns |
| --- | --- | --- |
| `createUser(data)` | `{ email, passwordHash, name, roles, emailVerified, tokenVersion, disabled, createdAt, updatedAt, ...extra }` | created user **with `id`** |
| `findUserByEmail(email)` | lower-cased email | user or `null` |
| `findUserById(id)` | string id | user or `null` |
| `updateUser(id, fields)` | id, partial fields | updated user, or `null` if not found |
| `listUsers({ limit, offset, search })` | paging, and lower-cased text to find in `email` (may be empty) | `{ users, total }`, newest first |
| `deleteUser(id)` | id | anything; must also delete all of that user's tokens and identities |
| `findUserIdByIdentity(provider, providerUserId)` | e.g. `google`, the provider's user id | user id or `null` |
| `linkIdentity({ userId, provider, providerUserId })` | link | anything; throws `Errors.identityTaken()` if already linked |
| `saveToken(record)` | `{ userId, tokenHash, type, expiresAt, meta }` | anything |
| `findToken(tokenHash, type)` | hash, type | record or `null` |
| `consumeToken(tokenHash, type)` | hash, type | record or `null`; **must be atomic** |
| `deleteToken(tokenHash)` | hash | anything |
| `deleteUserTokens(userId, type)` | id, type | anything |
| `deleteExpiredTokens()` | nothing | anything |

Rules:
- `email` must be unique (add a unique index). On a duplicate, `createUser` and `updateUser` must throw `Errors.emailTaken()`.
- `consumeToken` must find and delete in one atomic operation, so that concurrent calls with one token return the record exactly once.
- `listUsers` must treat `search` as literal text, not as a pattern.
- Lookups by an id that is malformed for your database must return `null`, not throw.
- `passwordHash` can be `null`, for accounts that only sign in with a provider.
- Users must expose `id` (string-able). Mongo's `_id` is mapped to `id` in `mongoAdapter.js`.
- `tokenHash` should be indexed/unique.
- Optional: `init()` — create tables/indexes. Called by you, not by the core.

Test your own adapter against the same suite, with `node --test`:

```js
import { runAdapterContract } from 'node-auth-kit/testing';
runAdapterContract('mysql', () => mysqlAdapter({ pool }));
```
