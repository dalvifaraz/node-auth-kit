/**
 * MongoDB adapter (official `mongodb` driver).
 *   npm install mongodb
 *
 *   const client = new MongoClient(process.env.MONGO_URL); await client.connect();
 *   const adapter = mongoAdapter({ db: client.db('myapp') });
 *   await adapter.init(); // indexes
 */
import { Errors } from '../utils/errors.js';

const DUPLICATE_KEY = 11000;

export function mongoAdapter({ db, usersCollection = 'users', tokensCollection = 'auth_tokens', ObjectId }) {
  const users = db.collection(usersCollection);
  const tokens = db.collection(tokensCollection);

  // ObjectId can be injected; otherwise resolved lazily so `mongodb` stays an optional dependency.
  let OID = ObjectId;
  const toId = async (id) => {
    OID ??= (await import('mongodb')).ObjectId;
    return OID.isValid(id) ? new OID(String(id)) : null;
  };
  const map = (doc) => {
    if (!doc) return null;
    const { _id, ...rest } = doc;
    return { id: String(_id), ...rest };
  };

  const mapToken = (doc) => {
    if (!doc) return null;
    const { _id, ...rest } = doc;
    return rest;
  };

  return {
    async init() {
      await users.createIndex({ email: 1 }, { unique: true });
      await tokens.createIndex({ tokenHash: 1 }, { unique: true });
      await tokens.createIndex({ userId: 1, type: 1 });
      await tokens.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // auto-cleanup
    },
    async createUser(data) {
      try {
        const { insertedId } = await users.insertOne({ ...data });
        return map({ _id: insertedId, ...data });
      } catch (err) {
        throw err?.code === DUPLICATE_KEY ? Errors.emailTaken() : err;
      }
    },
    async findUserByEmail(email) {
      return map(await users.findOne({ email }));
    },
    async findUserById(id) {
      const _id = await toId(id);
      return _id ? map(await users.findOne({ _id })) : null;
    },
    async updateUser(id, fields) {
      const _id = await toId(id);
      if (!_id) return null;
      const res = await users.findOneAndUpdate({ _id }, { $set: fields }, { returnDocument: 'after' });
      return map(res?.value ?? res);
    },
    async saveToken(record) {
      await tokens.insertOne({ ...record });
    },
    async findToken(tokenHash, type) {
      return mapToken(await tokens.findOne({ tokenHash, type }));
    },
    async consumeToken(tokenHash, type) {
      return mapToken(await tokens.findOneAndDelete({ tokenHash, type }));
    },
    async deleteToken(tokenHash) {
      await tokens.deleteOne({ tokenHash });
    },
    async deleteExpiredTokens() {
      await tokens.deleteMany({ expiresAt: { $lt: new Date() } });
    },
    async deleteUserTokens(userId, type) {
      await tokens.deleteMany({ userId: String(userId), type });
    },
  };
}
