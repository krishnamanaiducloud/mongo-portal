// ServiceProvider for the mongosh runtime running inside the sandbox iframe.
//
// mongosh (shell-api) calls these methods as if they were the Node.js driver.
// Each call becomes one RPC to the parent page broker, which forwards it to
// the portal API (POST /api/v1/shell). The sandbox has no network access and
// no credentials of its own.

/* eslint-disable @typescript-eslint/no-explicit-any */
import * as bson from 'bson';

export type Rpc = (op: string, args: Record<string, unknown>) => Promise<any>;

type Doc = Record<string, any>;

const FORBIDDEN_CURSOR_FLAGS = ['noCursorTimeout', 'tailable', 'awaitData', 'exhaust', 'oplogReplay'];

/** Error shaped like a driver MongoServerError so mongosh prints it naturally. */
export class PortalShellError extends Error {
  code?: number;
  codeName?: string;
  constructor(name: string, message: string, code?: number, codeName?: string) {
    super(message);
    this.name = name;
    this.code = code;
    this.codeName = codeName;
  }
}

function unsupported(what: string): never {
  throw new PortalShellError('MongoshUnimplementedError', `${what} is not supported in the portal shell`);
}

function toNumber(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof (v as { toNumber?: () => number }).toNumber === 'function') return (v as { toNumber: () => number }).toNumber();
  return Number(v);
}

/** Copies only the named option keys that are set. */
function pick(src: Doc | undefined, keys: string[]): Doc {
  const out: Doc = {};
  if (!src) return out;
  for (const k of keys) if (src[k] !== undefined) out[k] = src[k];
  return out;
}

const FIND_OPTS = ['projection', 'sort', 'skip', 'limit', 'hint', 'collation', 'comment', 'min', 'max', 'returnKey', 'showRecordId', 'allowDiskUse', 'batchSize', 'maxTimeMS'];
const AGG_OPTS = ['allowDiskUse', 'batchSize', 'collation', 'hint', 'comment', 'let', 'maxTimeMS'];
const WRITE_OPTS = ['upsert', 'arrayFilters', 'hint', 'collation'];
const FAM_OPTS = ['projection', 'sort', 'returnDocument', 'returnNewDocument', 'returnOriginal', 'upsert', 'arrayFilters', 'hint', 'collation', 'maxTimeMS'];

/** A lazily opened cursor backed by a server-side cursor in the portal. */
export class PortalCursor {
  private options: Doc;
  private buffer: Doc[] = [];
  private id = '';
  private started = false;
  private exhausted = false;
  private killed = false;
  private readonly rpc: Rpc;
  private readonly openOp: 'find' | 'aggregate';
  private readonly base: Doc;

  constructor(rpc: Rpc, openOp: 'find' | 'aggregate', base: Doc, options: Doc) {
    this.rpc = rpc;
    this.openOp = openOp;
    this.base = base;
    this.options = { ...options };
  }

  private set(key: string, value: unknown) {
    if (this.started) throw new PortalShellError('MongoshInvalidInputError', 'Cursor is already open; options cannot be changed');
    this.options[key] = value;
  }

  limit(n: number) { this.set('limit', n); }
  skip(n: number) { this.set('skip', n); }
  sort(s: Doc) { this.set('sort', s); }
  project(p: Doc) { this.set('projection', p); }
  hint(h: unknown) { this.set('hint', h); }
  collation(c: Doc) { this.set('collation', c); }
  comment(c: unknown) { this.set('comment', c); }
  min(m: Doc) { this.set('min', m); }
  max(m: Doc) { this.set('max', m); }
  returnKey(v: boolean) { this.set('returnKey', v); }
  showRecordId(v: boolean) { this.set('showRecordId', v); }
  allowDiskUse(v = true) { this.set('allowDiskUse', v); }
  batchSize(n: number) { this.options.batchSize = n; }
  maxTimeMS(n: number) { this.set('maxTimeMS', n); }
  maxAwaitTimeMS() { /* not applicable: tailable cursors are not supported */ }
  addCursorFlag(flag: string, value: boolean) {
    if (value && FORBIDDEN_CURSOR_FLAGS.includes(flag)) unsupported(`Cursor flag ${flag}`);
  }
  withReadPreference() { return this; }
  withReadConcern() { return this; }

  get closed(): boolean {
    return this.killed || (this.started && this.exhausted);
  }

  private async fill(): Promise<void> {
    while (this.buffer.length === 0 && !this.closed) {
      let reply: { id: string; batch: Doc[]; exhausted: boolean };
      if (!this.started) {
        this.started = true;
        const opts = pick(this.options, this.openOp === 'find' ? FIND_OPTS : AGG_OPTS);
        reply = await this.rpc(this.openOp, { ...this.base, options: opts });
      } else {
        reply = await this.rpc('getMore', { id: this.id, batchSize: this.options.batchSize ?? 100 });
      }
      this.id = reply.id || this.id;
      this.buffer.push(...(reply.batch ?? []));
      this.exhausted = !!reply.exhausted;
    }
  }

  async hasNext(): Promise<boolean> {
    await this.fill();
    return this.buffer.length > 0;
  }

  async next(): Promise<Doc | null> {
    return (await this.hasNext()) ? (this.buffer.shift() ?? null) : null;
  }

  tryNext(): Promise<Doc | null> {
    return this.next();
  }

  async toArray(): Promise<Doc[]> {
    const out: Doc[] = [];
    while (await this.hasNext()) out.push(...this.buffer.splice(0));
    return out;
  }

  bufferedCount(): number {
    return this.buffer.length;
  }

  readBufferedDocuments(n?: number): Doc[] {
    return this.buffer.splice(0, n ?? this.buffer.length);
  }

  async close(): Promise<void> {
    if (this.id && !this.exhausted && !this.killed) {
      await this.rpc('killCursor', { id: this.id }).catch(() => undefined);
    }
    this.killed = true;
    this.buffer = [];
  }

  async count(): Promise<number> {
    const r = await this.rpc('countDocuments', { ...this.base, options: pick(this.options, ['limit', 'skip', 'hint', 'collation', 'maxTimeMS']) });
    return toNumber(r.n);
  }

  async explain(verbosity?: string): Promise<Doc> {
    const r = await this.rpc('explain', {
      ...this.base,
      kind: this.openOp,
      options: pick(this.options, FIND_OPTS),
      verbosity: typeof verbosity === 'string' ? verbosity : 'queryPlanner',
    });
    return r.result;
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<Doc, void, void> {
    while (await this.hasNext()) yield this.buffer.shift() as Doc;
  }
}

function defaultIndexName(key: Doc): string {
  return Object.entries(key).map(([k, v]) => `${k}_${String(v)}`).join('_');
}

export interface ProviderOptions {
  initialDb: string;
  uri: string;
}

/**
 * Implements the @mongosh/service-provider-core ServiceProvider interface
 * (structurally; the type is not imported to keep the sandbox decoupled from
 * driver typings).
 */
export class PortalServiceProvider {
  readonly bsonLibrary = bson;
  readonly platform = 'Browser';
  readonly initialDb: string;
  private readonly rpc: Rpc;
  private readonly uri: string;
  private connInfo: Doc | null = null;

  constructor(rpc: Rpc, opts: ProviderOptions) {
    this.rpc = rpc;
    this.initialDb = opts.initialDb;
    this.uri = opts.uri;
  }

  // ---- Admin ----
  getURI() { return this.uri; }
  getRawClient() { return undefined; }
  getFleOptions() { return undefined; }
  getReadPreference() { return { mode: 'primary' }; }
  getReadConcern() { return undefined; }
  getWriteConcern() { return undefined; }
  readPreferenceFromOptions() { return undefined; }

  getTopologyDescription() {
    const hello = this.connInfo?.hello;
    if (!hello) return undefined;
    return hello.setName
      ? { type: hello.primary ? 'ReplicaSetWithPrimary' : 'ReplicaSetNoPrimary', setName: hello.setName }
      : { type: 'Single', setName: null };
  }

  async getConnectionInfo() {
    const info = await this.rpc('connectionInfo', {});
    this.connInfo = info;
    const version = info.buildInfo?.version ?? '';
    return {
      buildInfo: info.buildInfo ?? null,
      resolvedHostname: info.hello?.me,
      extraInfo: {
        uri: this.uri,
        is_atlas: false,
        is_localhost: false,
        is_do_url: false,
        server_version: version,
        is_enterprise: Array.isArray(info.buildInfo?.modules) && info.buildInfo.modules.includes('enterprise'),
        node_version: '',
        dl_version: '',
      },
    };
  }

  async listDatabases(_db: string, options?: Doc) {
    return this.rpc('listDatabases', pick(options, ['filter', 'nameOnly']));
  }

  async createCollection(db: string, coll: string, options?: Doc) {
    await this.rpc('createCollection', { db, coll, options: pick(options, ['capped', 'size', 'max', 'validator', 'validationLevel', 'validationAction', 'collation', 'expireAfterSeconds', 'timeseries', 'clusteredIndex', 'changeStreamPreAndPostImages', 'viewOn', 'pipeline']) });
    return { ok: 1 };
  }

  getNewConnection(): never { return unsupported('Connecting to another deployment (Mongo()/connect())'); }
  authenticate(): never { return unsupported('db.auth(); sign in through the portal login instead'); }
  resetConnectionOptions(): never { return unsupported('Changing connection options'); }
  startSession(): never { return unsupported('Sessions and transactions'); }
  createClientEncryption(): never { return unsupported('Client-side field level encryption'); }
  async close() { /* the portal owns the connection */ }
  async suspend() { return async () => undefined; }

  // ---- Readable ----
  find(db: string, coll: string, filter: Doc = {}, options?: Doc) {
    return new PortalCursor(this.rpc, 'find', { db, coll, filter }, pick(options, FIND_OPTS));
  }

  aggregate(db: string, coll: string, pipeline: Doc[] = [], options?: Doc) {
    return new PortalCursor(this.rpc, 'aggregate', { db, coll, pipeline }, pick(options, AGG_OPTS));
  }

  aggregateDb(db: string, pipeline: Doc[] = [], options?: Doc) {
    return new PortalCursor(this.rpc, 'aggregate', { db, coll: '', pipeline }, pick(options, AGG_OPTS));
  }

  async count(db: string, coll: string, query: Doc = {}, options?: Doc) {
    return this.countDocuments(db, coll, query, options);
  }

  async countDocuments(db: string, coll: string, filter: Doc = {}, options?: Doc) {
    const r = await this.rpc('countDocuments', { db, coll, filter, options: pick(options, ['limit', 'skip', 'hint', 'collation', 'maxTimeMS']) });
    return toNumber(r.n);
  }

  async estimatedDocumentCount(db: string, coll: string) {
    const r = await this.rpc('estimatedDocumentCount', { db, coll });
    return toNumber(r.n);
  }

  async distinct(db: string, coll: string, key: string, filter: Doc = {}, options?: Doc) {
    const r = await this.rpc('distinct', { db, coll, key, filter, options: pick(options, ['collation', 'maxTimeMS']) });
    return r.values;
  }

  async getIndexes(db: string, coll: string) {
    const r = await this.rpc('getIndexes', { db, coll });
    return r.indexes;
  }

  async listCollections(db: string, filter: Doc = {}, options?: Doc) {
    const r = await this.rpc('listCollections', { db, filter, nameOnly: !!options?.nameOnly });
    return r.collections;
  }

  watch(): never { return unsupported('Change streams (watch)'); }
  async getSearchIndexes(): Promise<never> { return unsupported('Atlas Search indexes'); }

  // ---- Writable ----
  async runCommand(db: string, spec: Doc) {
    const r = await this.rpc('runCommand', { db, command: spec });
    return r.result;
  }

  async runCommandWithCheck(db: string, spec: Doc) {
    const result = await this.runCommand(db, spec);
    if (result && result.ok !== undefined && toNumber(result.ok) !== 1) {
      throw new PortalShellError('MongoServerError', result.errmsg ?? 'command failed', result.code, result.codeName);
    }
    return result;
  }

  runCursorCommand(): never { return unsupported('runCursorCommand'); }

  async insertOne(db: string, coll: string, document: Doc) {
    const r = await this.rpc('insertOne', { db, coll, document });
    return { acknowledged: true, insertedId: r.insertedId };
  }

  async insertMany(db: string, coll: string, documents: Doc[], options?: Doc) {
    const r = await this.rpc('insertMany', { db, coll, documents, ...pick(options, ['ordered']) });
    const insertedIds: Record<number, unknown> = {};
    (r.insertedIds as unknown[]).forEach((id, i) => (insertedIds[i] = id));
    return { acknowledged: true, insertedCount: (r.insertedIds as unknown[]).length, insertedIds };
  }

  private updateResult(r: Doc) {
    return {
      acknowledged: true,
      matchedCount: toNumber(r.matchedCount),
      modifiedCount: toNumber(r.modifiedCount),
      upsertedCount: toNumber(r.upsertedCount),
      upsertedId: r.upsertedId ?? null,
    };
  }

  async updateOne(db: string, coll: string, filter: Doc, update: Doc | Doc[], options?: Doc) {
    return this.updateResult(await this.rpc('updateOne', { db, coll, filter, update, options: pick(options, WRITE_OPTS) }));
  }

  async updateMany(db: string, coll: string, filter: Doc, update: Doc | Doc[], options?: Doc) {
    return this.updateResult(await this.rpc('updateMany', { db, coll, filter, update, options: pick(options, WRITE_OPTS) }));
  }

  async replaceOne(db: string, coll: string, filter: Doc, replacement: Doc, options?: Doc) {
    return this.updateResult(await this.rpc('replaceOne', { db, coll, filter, replacement, options: pick(options, WRITE_OPTS) }));
  }

  async deleteOne(db: string, coll: string, filter: Doc, options?: Doc) {
    const r = await this.rpc('deleteOne', { db, coll, filter, options: pick(options, ['hint', 'collation']) });
    return { acknowledged: true, deletedCount: toNumber(r.deletedCount) };
  }

  async deleteMany(db: string, coll: string, filter: Doc, options?: Doc) {
    const r = await this.rpc('deleteMany', { db, coll, filter, options: pick(options, ['hint', 'collation']) });
    return { acknowledged: true, deletedCount: toNumber(r.deletedCount) };
  }

  async findOneAndDelete(db: string, coll: string, filter: Doc, options?: Doc) {
    return (await this.rpc('findOneAndDelete', { db, coll, filter, options: pick(options, FAM_OPTS) })).value;
  }

  async findOneAndReplace(db: string, coll: string, filter: Doc, replacement: Doc, options?: Doc) {
    return (await this.rpc('findOneAndReplace', { db, coll, filter, replacement, options: pick(options, FAM_OPTS) })).value;
  }

  async findOneAndUpdate(db: string, coll: string, filter: Doc, update: Doc | Doc[], options?: Doc) {
    return (await this.rpc('findOneAndUpdate', { db, coll, filter, update, options: pick(options, FAM_OPTS) })).value;
  }

  async bulkWrite(db: string, coll: string, operations: Doc[], options?: Doc) {
    const r = await this.rpc('bulkWrite', { db, coll, operations, ...pick(options, ['ordered']) });
    const upsertedIds: Record<string, unknown> = { ...(r.upsertedIds ?? {}) };
    return {
      ok: 1,
      acknowledged: true,
      insertedCount: toNumber(r.insertedCount),
      matchedCount: toNumber(r.matchedCount),
      modifiedCount: toNumber(r.modifiedCount),
      deletedCount: toNumber(r.deletedCount),
      upsertedCount: toNumber(r.upsertedCount),
      insertedIds: {},
      upsertedIds,
    };
  }

  clientBulkWrite(): never { return unsupported('Mongo.bulkWrite (client bulk write)'); }
  initializeBulkOp(): never { return unsupported('Legacy Bulk API (initializeOrderedBulkOp); use bulkWrite()'); }

  async createIndexes(db: string, coll: string, specs: Doc[]) {
    await this.rpc('createIndexes', { db, coll, specs });
    return specs.map((s) => (s.name as string) ?? defaultIndexName(s.key ?? {}));
  }

  async dropCollection(db: string, coll: string) {
    const r = await this.rpc('dropCollection', { db, coll });
    return !!r.dropped;
  }

  async dropDatabase(db: string) {
    return this.rpc('dropDatabase', { db });
  }

  async renameCollection(db: string, from: string, to: string, options?: Doc) {
    await this.rpc('renameCollection', { db, from, to, dropTarget: !!options?.dropTarget });
    return {};
  }

  createSearchIndexes(): never { return unsupported('Atlas Search indexes'); }
  dropSearchIndex(): never { return unsupported('Atlas Search indexes'); }
  updateSearchIndex(): never { return unsupported('Atlas Search indexes'); }
}
