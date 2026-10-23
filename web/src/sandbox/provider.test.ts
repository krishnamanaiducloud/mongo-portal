// @vitest-environment node
//
// Runs the real mongosh runtime (evaluator, shell-api) against
// PortalServiceProvider with a fake portal backend, and checks the exact
// operations mongosh asks the portal to perform.
/* eslint-disable @typescript-eslint/no-explicit-any */
// @ts-expect-error -- Node built-in used only by this test; @types/node is deliberately not part of the browser build
import { createContext, runInContext } from 'node:vm';
import { describe, expect, it } from 'vitest';
import * as bson from 'bson';
import { OpenContextRuntime } from '@mongosh/browser-runtime-core';
import { PortalServiceProvider, type Rpc } from './provider';
import { toDisplay } from './display';

type Call = { op: string; args: Record<string, unknown> };

function setup(handler: (op: string, args: Record<string, any>) => unknown) {
  const calls: Call[] = [];
  // Round-trip through canonical Extended JSON exactly like the real transport.
  const rpc: Rpc = async (op, args) => {
    const wire = JSON.parse(bson.EJSON.stringify(args, { relaxed: false }));
    const parsedArgs = bson.EJSON.deserialize(wire, { relaxed: false }) as Record<string, any>;
    calls.push({ op, args: parsedArgs });
    const res = await handler(op, parsedArgs);
    return bson.EJSON.parse(bson.EJSON.stringify(res, { relaxed: false }), { relaxed: false });
  };
  const sp = new PortalServiceProvider(rpc, { initialDb: 'app', uri: 'mongodb://primary.portal/' });
  // A fresh realm per runtime, like each sandbox iframe in the browser.
  const ctx = createContext({});
  const rt = new OpenContextRuntime(sp as never, { sloppyEval: (c: string) => runInContext(c, ctx), getContextObject: () => ctx });
  const prints: unknown[] = [];
  rt.setEvaluationListener({ onPrint: (v) => void prints.push(...v.map(toDisplay)), onPrompt: async () => '' });
  return { rt, calls, prints };
}

const conn = { buildInfo: { version: '8.0.4', modules: [] }, hello: { setName: 'rs0', primary: 'rs1:27017', me: 'rs1:27017' } };
const docs = Array.from({ length: 30 }, (_, i) => ({ _id: new bson.ObjectId(), n: i, at: new Date(0) }));

function backend(op: string, a: Record<string, any>) {
  switch (op) {
    case 'connectionInfo':
      return conn;
    case 'find':
      return { id: 'c1', batch: docs.slice(0, 25), exhausted: false };
    case 'getMore':
      return { id: 'c1', batch: docs.slice(25), exhausted: true };
    case 'aggregate':
      return { id: '', batch: [{ total: 30 }], exhausted: true };
    case 'countDocuments':
      return { n: bson.Long.fromNumber(30) };
    case 'insertOne':
      return { insertedId: a.document._id ?? new bson.ObjectId() };
    case 'insertMany':
      return { insertedIds: a.documents.map((_: unknown, i: number) => i) };
    case 'updateMany':
      return { matchedCount: 3, modifiedCount: 3, upsertedCount: 0, upsertedId: null };
    case 'createIndexes':
      return { result: { ok: 1 } };
    case 'listCollections':
      return { collections: [{ name: 'orders', type: 'collection' }] };
    case 'runCommand':
      return { result: { ok: 1, db: a.db, collections: 1 } };
    case 'listDatabases':
      return { databases: [{ name: 'app', sizeOnDisk: 4096, empty: false }], ok: 1 };
  }
  throw new Error(`unexpected op ${op}`);
}

describe('PortalServiceProvider with the real mongosh runtime', () => {
  it('runs find with cursor modifiers and BSON types', async () => {
    const { rt, calls } = setup(backend);
    const r = await rt.evaluate('db.orders.find({ _id: ObjectId("507f1f77bcf86cd799439011"), at: { $gte: ISODate("2024-01-01") } }, { n: 1 }).sort({ n: -1 }).skip(2).limit(5)');
    expect(r.type).toBe('Cursor');
    const find = calls.find((c) => c.op === 'find')!;
    expect(find.args.db).toBe('app');
    expect(find.args.coll).toBe('orders');
    const filter = find.args.filter as Record<string, any>;
    expect(filter._id).toBeInstanceOf(bson.ObjectId);
    expect(filter.at.$gte).toBeInstanceOf(Date);
    const opts = find.args.options as Record<string, any>;
    expect(bson.EJSON.serialize(opts.sort)).toEqual({ n: -1 });
    expect(Number(opts.skip)).toBe(2);
    expect(Number(opts.limit)).toBe(5);
    expect(bson.EJSON.serialize(opts.projection)).toEqual({ n: 1 });
    const out = toDisplay(r).value as { documents: unknown[]; cursorHasMore: boolean };
    expect(out.documents.length).toBe(20);
    expect(out.cursorHasMore).toBe(true);
  });

  it('supports JavaScript, cursor iteration across getMore, and printjson', async () => {
    const { rt, calls, prints } = setup(backend);
    const r = await rt.evaluate('let total = 0; db.orders.find().forEach(d => { total += d.n }); printjson({ total }); total');
    expect(r.printable).toBe(435); // 0 + 1 + ... + 29
    expect(calls.filter((c) => c.op === 'getMore')).toHaveLength(1);
    expect(prints).toHaveLength(1);
  });

  it('runs toArray, it, aggregate, count and show commands', async () => {
    const { rt } = setup(backend);
    expect((await rt.evaluate('db.orders.find().toArray().length')).printable).toBe(30);
    await rt.evaluate('db.orders.find()');
    expect((await rt.evaluate('it')).type).toBe('CursorIterationResult');
    const agg = await rt.evaluate('db.orders.aggregate([{ $group: { _id: null, total: { $sum: 1 } } }])');
    expect(agg.type).toBe('AggregationCursor');
    expect((await rt.evaluate('db.orders.countDocuments({ n: { $gt: 1 } })')).printable).toBe(30);
    expect((await rt.evaluate('show dbs')).type).toBe('ShowDatabasesResult');
    expect((await rt.evaluate('show collections')).type).toBe('ShowCollectionsResult');
    expect((await rt.evaluate('db.getName()')).printable).toBe('app');
  });

  it('maps writes and index creation to portal operations', async () => {
    const { rt, calls } = setup(backend);
    const ins = await rt.evaluate('db.orders.insertOne({ sku: "A1", price: NumberDecimal("9.99") })');
    expect(ins.type).toBe('InsertOneResult');
    const doc = calls.find((c) => c.op === 'insertOne')!.args.document as Record<string, any>;
    expect(doc.price).toBeInstanceOf(bson.Decimal128);
    await rt.evaluate('db.orders.insertMany([{ a: 1 }, { a: 2 }])');
    expect((calls.find((c) => c.op === 'insertMany')!.args.documents as unknown[]).length).toBe(2);
    const upd = await rt.evaluate('db.orders.updateMany({ a: { $gt: 0 } }, { $inc: { a: 1 } })');
    expect(upd.type).toBe('UpdateResult');
    expect(bson.EJSON.serialize(calls.find((c) => c.op === 'updateMany')!.args.update)).toEqual({ $inc: { a: 1 } });
    const idx = await rt.evaluate('db.orders.createIndex({ sku: 1 }, { unique: true })');
    expect(idx.printable).toBe('sku_1');
  });

  it('refuses operations the portal does not support', async () => {
    const { rt } = setup(backend);
    for (const code of ['new Mongo("mongodb://attacker:27017")', 'db.getMongo().startSession()', 'db.orders.watch()']) {
      await expect(rt.evaluate(code), code).rejects.toThrow();
    }
  });

  it('autocompletes collection names and methods with the classic completer used in the browser', async () => {
    const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process.env;
    const prev = env.USE_NEW_AUTOCOMPLETE;
    env.USE_NEW_AUTOCOMPLETE = '0';
    try {
      const { rt } = setup(backend);
      expect((await rt.getCompletions('db.ord')).map((c) => c.completion)).toContain('db.orders');
      expect((await rt.getCompletions('db.orders.fin')).map((c) => c.completion)).toEqual(
        expect.arrayContaining(['db.orders.find', 'db.orders.findOne']),
      );
    } finally {
      env.USE_NEW_AUTOCOMPLETE = prev;
    }
  });

  it('surfaces server errors with their code name', async () => {
    const { rt } = setup((op) => {
      if (op === 'connectionInfo') return conn;
      const e = new Error('not authorized on app to execute command') as Error & { code: number; codeName: string };
      e.name = 'MongoServerError';
      e.code = 13;
      e.codeName = 'Unauthorized';
      throw e;
    });
    await expect(rt.evaluate('db.orders.insertOne({})')).rejects.toMatchObject({ code: 13, codeName: 'Unauthorized' });
  });
});
