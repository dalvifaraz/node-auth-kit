import nodemailer from 'nodemailer';

const escapeHtml = (value) =>
  String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function formatDuration(ms) {
  const minutes = Math.round(ms / 60000);
  const [value, unit] = minutes % 1440 === 0 ? [minutes / 1440, 'day']
    : minutes % 60 === 0 ? [minutes / 60, 'hour']
      : [minutes, 'minute'];
  return `${value} ${unit}${value === 1 ? '' : 's'}`;
}

function message({ user, appName, subject, intro, action, link, expiresIn, ignore }) {
  const greeting = user.name ? `Hi ${user.name},` : 'Hi,';
  const expiry = `This link expires in ${expiresIn}.`;
  return {
    subject,
    text: [greeting, intro, `${action}: ${link}`, expiry, ignore, `- ${appName}`].join('\n\n'),
    html: [
      `<p>${escapeHtml(greeting)}</p>`,
      `<p>${escapeHtml(intro)}</p>`,
      `<p><a href="${escapeHtml(link)}">${escapeHtml(action)}</a></p>`,
      `<p>${escapeHtml(expiry)}</p>`,
      `<p>${escapeHtml(ignore)}</p>`,
      `<p>${escapeHtml(appName)}</p>`,
    ].join('\n'),
  };
}

function notice({ user, appName, subject, lines }) {
  const greeting = user.name ? `Hi ${user.name},` : 'Hi,';
  const parts = [greeting, ...lines, appName];
  return { subject, text: parts.join('\n\n'), html: parts.map((p) => `<p>${escapeHtml(p)}</p>`).join('\n') };
}

const defaultTemplates = {
  passwordReset: (data) => message({
    ...data,
    subject: `Reset your ${data.appName} password`,
    intro: `We received a request to reset your ${data.appName} password.`,
    action: 'Reset your password',
    ignore: 'If you did not ask for this, you can ignore this email and your password will stay the same.',
  }),
  verifyEmail: (data) => message({
    ...data,
    subject: `Verify your ${data.appName} email`,
    intro: `Please confirm your email address to finish setting up your ${data.appName} account.`,
    action: 'Verify your email',
    ignore: 'If you did not create this account, you can ignore this email.',
  }),
  emailChange: (data) => message({
    ...data,
    subject: `Confirm your new ${data.appName} email`,
    intro: `Please confirm this address to use it for your ${data.appName} account.`,
    action: 'Confirm your new email',
    ignore: 'If you did not ask for this, you can ignore this email and nothing will change.',
  }),
  emailChanged: (data) => notice({
    ...data,
    subject: `Your ${data.appName} email was changed`,
    lines: [
      `The email address for your ${data.appName} account was changed to ${data.newEmail}.`,
      'If you did not do this, contact support straight away.',
    ],
  }),
};

/** Reads email settings from the environment. Returns null when SMTP_URL is not set. */
export function emailConfigFromEnv(env = process.env) {
  if (!env.SMTP_URL) return null;
  return { smtp: env.SMTP_URL, from: env.EMAIL_FROM, appUrl: env.APP_URL, appName: env.APP_NAME };
}

/**
 * Builds the email hooks: password reset, verification, and email change with its notice to the old address.
 *   { smtp | transport, from, appUrl, appName, resetPath, verifyPath, changeEmailPath, templates }
 * `smtp` is an SMTP URL or nodemailer options. `transport` is anything with sendMail().
 */
export function createEmailHooks(options, { resetTokenTtlMs, verifyTokenTtlMs }) {
  const {
    smtp, transport, from, appUrl, appName = 'Your app',
    resetPath = '/reset-password', verifyPath = '/verify-email', changeEmailPath = '/confirm-email-change', templates = {},
  } = options;

  if (!smtp && !transport) throw new Error('createAuth: `email` needs `smtp` or `transport`');
  if (!from) throw new Error('createAuth: `email.from` is required');
  if (!URL.canParse(appUrl ?? '')) throw new Error('createAuth: `email.appUrl` must be a full URL');

  const mailer = transport ?? nodemailer.createTransport(smtp);
  const linkTo = (path, token) => `${appUrl.replace(/\/+$/, '')}${path}?token=${encodeURIComponent(token)}`;

  const send = async (template, user, link, ttlMs, extra = {}) => {
    const { subject, text, html } = await template({ user, link, appName, expiresIn: formatDuration(ttlMs), ...extra });
    await mailer.sendMail({ from, to: extra.to ?? user.email, subject, text, html });
  };

  return {
    sendPasswordResetEmail: ({ user, token }) =>
      send(templates.passwordReset ?? defaultTemplates.passwordReset, user, linkTo(resetPath, token), resetTokenTtlMs),
    sendVerificationEmail: ({ user, token }) =>
      send(templates.verifyEmail ?? defaultTemplates.verifyEmail, user, linkTo(verifyPath, token), verifyTokenTtlMs),
    sendEmailChangeEmail: ({ user, newEmail, token }) =>
      send(templates.emailChange ?? defaultTemplates.emailChange, user, linkTo(changeEmailPath, token), verifyTokenTtlMs, { to: newEmail, newEmail }),
    sendEmailChangedNotice: ({ user, newEmail }) =>
      send(templates.emailChanged ?? defaultTemplates.emailChanged, user, null, 0, { newEmail }),
  };
}
