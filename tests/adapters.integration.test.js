/**
 * Runs the adapter contract against real databases. Each suite is skipped unless
 * its connection string is set (CI sets both):
 *   DATABASE_URL=postgres://... MONGO_URL=mongodb://... npm test
 */
import { after, test } from 'node:test';
import { runAdapterContract } from './adapterContract.js';
import { postgresAdapter } from '../src/adapters/postgresAdapter.js';
import { mongoAdapter } from '../src/adapters/mongoAdapter.js';

const { DATABASE_URL, MONGO_URL } = process.env;

if (DATABASE_URL) {
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({ connectionString: DATABASE_URL });
  const adapter = postgresAdapter({ pool });
  await adapter.init();
  runAdapterContract('postgres', () => adapter);
  after(() => pool.end());
} else {
  test('adapter contract: postgres', { skip: 'DATABASE_URL not set' }, () => {});
}

if (MONGO_URL) {
  const { MongoClient, ObjectId } = await import('mongodb');
  const client = await new MongoClient(MONGO_URL).connect();
  const adapter = mongoAdapter({ db: client.db('auth_kit_test'), ObjectId });
  await adapter.init();
  runAdapterContract('mongo', () => adapter);
  after(() => client.close());
} else {
  test('adapter contract: mongo', { skip: 'MONGO_URL not set' }, () => {});
}
