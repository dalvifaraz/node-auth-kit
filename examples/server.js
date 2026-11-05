/**
 * Example app. Pick the database with DB_DRIVER=memory | mongo | postgres in .env
 *   npm start
 */
import 'dotenv/config';
import express from 'express';
import { createAuth } from '../src/index.js';

async function buildAdapter() {
  switch (process.env.DB_DRIVER ?? 'memory') {
    case 'mongo': {
      const { MongoClient, ObjectId } = await import('mongodb');
      const client = new MongoClient(process.env.MONGO_URL);
      await client.connect();
      const { mongoAdapter } = await import('../src/adapters/mongoAdapter.js');
      const adapter = mongoAdapter({ db: client.db(process.env.MONGO_DB ?? 'auth'), ObjectId });
      await adapter.init();
      return adapter;
    }
    case 'postgres': {
      const pg = (await import('pg')).default;
      const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
      const { postgresAdapter } = await import('../src/adapters/postgresAdapter.js');
      const adapter = postgresAdapter({ pool });
      await adapter.init();
      return adapter;
    }
    default: {
      const { memoryAdapter } = await import('../src/adapters/memoryAdapter.js');
      console.warn('[example] Using in-memory DB — data resets on restart');
      return memoryAdapter();
    }
  }
}

const auth = createAuth({
  adapter: await buildAdapter(),
  jwtSecret: process.env.JWT_SECRET,
  accessTokenTtl: process.env.ACCESS_TOKEN_TTL ?? '15m',
  allowedRegisterFields: ['phone'],
  hooks: {
    // Plug in your email provider (SES, SendGrid, Resend, Nodemailer...)
    sendPasswordResetEmail: async ({ user, token }) =>
      console.log(`[email] reset link for ${user.email}: ${process.env.APP_URL}/reset?token=${token}`),
    sendVerificationEmail: async ({ user, token }) =>
      console.log(`[email] verify link for ${user.email}: ${process.env.APP_URL}/verify?token=${token}`),
  },
});

const app = express();
app.set('trust proxy', 1); // correct req.ip behind a proxy/load balancer

app.use('/api/auth', auth.router);

// Any route can be protected with auth.authenticate
app.get('/api/profile', auth.authenticate, (req, res) => res.json({ hello: req.auth.email }));
app.get('/api/admin', auth.authenticate, auth.requireRoles('admin'), (_req, res) => res.json({ ok: true }));

app.use(auth.errorHandler);

const port = process.env.PORT ?? 3000;
app.listen(port, () => console.log(`Auth server on http://localhost:${port}`));
