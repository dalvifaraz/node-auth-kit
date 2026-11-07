/**
 * Built-in sign-in providers. Each turns a provider access token into
 * { id, email, emailVerified, name }. URLs can be overridden per provider in settings.
 */
export const PROVIDERS = {
  google: {
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    scope: 'openid email profile',
    async getProfile(accessToken, fetchJson, settings) {
      const info = await fetchJson(settings.userInfoUrl ?? 'https://openidconnect.googleapis.com/v1/userinfo', accessToken);
      return { id: info.sub, email: info.email, emailVerified: info.email_verified === true, name: info.name ?? null };
    },
  },
  github: {
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    scope: 'read:user user:email',
    async getProfile(accessToken, fetchJson, settings) {
      const api = settings.apiUrl ?? 'https://api.github.com';
      const [user, emails] = await Promise.all([
        fetchJson(`${api}/user`, accessToken),
        fetchJson(`${api}/user/emails`, accessToken),
      ]);
      // Only the primary address, and only once GitHub has verified it.
      const primary = Array.isArray(emails) ? emails.find((e) => e.primary && e.verified) : null;
      return { id: String(user.id), email: primary?.email ?? null, emailVerified: Boolean(primary), name: user.name ?? user.login ?? null };
    },
  },
};

/** Reads sign-in settings from the environment. Returns null when no provider is configured. */
export function oauthConfigFromEnv(env = process.env) {
  const providers = {};
  if (env.GOOGLE_CLIENT_ID) providers.google = { clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET };
  if (env.GITHUB_CLIENT_ID) providers.github = { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET };
  if (!Object.keys(providers).length) return null;
  return {
    publicUrl: env.AUTH_PUBLIC_URL,
    redirectUrl: env.OAUTH_REDIRECT_URL,
    providers,
    cookieSecure: env.OAUTH_COOKIE_SECURE !== 'false',
  };
}
