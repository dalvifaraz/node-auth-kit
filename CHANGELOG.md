# Changelog

## 1.0.0

First release.

### Accounts

- Register, login, logout, logout everywhere and `/me`
- Change password, which keeps the caller signed in and ends every other session
- Forgot and reset password
- Email verification, which can be required before any tokens are given, with resend
- Change email, confirmed from the new address, with a notice to the old one
- Delete your own account, and an `onUserDeleted` hook for the app's own data
- Sign in with Google and GitHub, or another OAuth provider

### Sessions

- Short-lived JWT access tokens, checked against the database by default, so logout, password changes, role changes and disabled accounts apply at once
- Rotating refresh tokens, stored hashed and single use, with stolen-token detection
- Refresh token in an httpOnly cookie for browsers, or in the body for mobile and API clients
- `previousJwtSecrets` for changing the secret without failed requests

### Admin

- List and search users, set roles, and disable, enable or delete accounts
- Admins can't lock themselves out

### Email

- Reset, verification and email-change messages over SMTP, set up from environment variables
- Custom templates, or hooks to send email another way
- At most one email of each kind per account per minute, by default

### Databases

- PostgreSQL and MongoDB adapters, and an in-memory adapter for tests
- `adapter.init()` creates and updates tables and indexes
- Expired tokens deleted every hour
- Contract tests for other databases, exported as `node-auth-kit/testing`

### Protection

- bcrypt passwords, with the 72-byte limit enforced
- Rate limiting per IP and route
- Login and forgot-password don't reveal which emails are registered
- Only allowlisted user fields reach clients, and protected fields can't be set at signup
- Startup checks for weak or placeholder secrets and unsafe options
- Provider sign-in uses PKCE and a signed state cookie, accepts only provider-verified emails, and reclaims accounts registered by someone else in advance

### Compatibility

- Node.js 20 or newer
- Express 4.21 or newer, or Express 5
- PostgreSQL 13 or newer
- Tested in CI on Node 20, 22 and 24, against real PostgreSQL and MongoDB
