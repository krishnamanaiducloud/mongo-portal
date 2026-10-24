/** How the current user signed in. "" means anonymous (no SSO, no MongoDB session). */
export type IdentitySource = '' | 'openshift' | 'oidc' | 'header' | 'dev' | 'mongodb';

export interface OpenShiftStatus {
  state: 'available' | 'unavailable' | 'disabled';
  reason?: string;
  checkedAt?: string;
  issuer?: string;
}

/** Sign-in methods available right now. SSO sources are optional and passive. */
/** An OpenID Connect provider for portal sign-in. */
export interface OIDCOption {
  name: string;
  displayName: string;
  state: 'available' | 'unavailable';
  reason?: string;
  url: string;
}

export interface AuthOptions {
  openshift: OpenShiftStatus;
  oidc?: OIDCOption[];
  openshiftURL: string;
  header: boolean;
  dev: boolean;
  requireSSO: boolean;
  mongodbLogin: boolean;
}

/** UI permission hints keyed "resource:action" (and "audit:all"). */
export type GlobalPermissions = Record<string, boolean>;

export interface Me {
  authenticated: boolean;
  user: string;
  source: IdentitySource;
  sso: boolean;
  groups: string[];
  roles: string[];
  permissions: GlobalPermissions;
  csrfToken: string;
  hasSession: boolean;
  ssoLogoutURL: string;
  environment: string;
  build: { version: string; commit: string };
  auth: AuthOptions;
}

export type HealthState = 'unknown' | 'online' | 'degraded' | 'offline' | 'misconfigured' | 'disabled';

export interface ProfileHealth {
  state: HealthState;
  reason?: string;
  latencyMs?: number;
  setName?: string;
  checkedAt?: string;
}

export interface Profile {
  name: string;
  displayName: string;
  description?: string;
  defaultAuthSource: string;
  authMechanisms: string[];
  tlsMode: 'enabled' | 'disabled';
  clientCertificate: boolean;
  plaintextWarning: boolean;
  replicaSet?: string;
  health?: ProfileHealth;
  /** MONGODB-OIDC sign-in, when the profile offers it. */
  oidc?: { displayName: string; issuer: string; url: string };
}

export interface RoleRef {
  role: string;
  db: string;
}

export interface Principal {
  user: string;
  groups: string[] | null;
  source: IdentitySource;
}

export interface SessionInfo {
  handle: string;
  profile: string;
  profileInfo?: Profile;
  mongoUser: string;
  authSource: string;
  mechanism: string;
  tls: boolean;
  identity: Principal | null;
  portalRoles: string[] | null;
  permissions: GlobalPermissions;
  mongoRoles: RoleRef[] | null;
  createdAt: string;
  expiresAt: string;
  idleExpiresAt: string;
  idleTimeoutSeconds: number;
  csrfToken: string;
}

export interface Capabilities {
  find: boolean;
  insert: boolean;
  update: boolean;
  remove: boolean;
  createIndex: boolean;
  dropIndex: boolean;
  createCollection: boolean;
  dropCollection: boolean;
  listCollections: boolean;
  listIndexes: boolean;
  dbStats: boolean;
  collStats: boolean;
}

/** Portal RBAC decisions for one namespace. */
export interface PortalAccess {
  find: boolean;
  insert: boolean;
  update: boolean;
  remove: boolean;
  createIndex: boolean;
  dropIndex: boolean;
  createCollection: boolean;
  dropCollection: boolean;
  dropDatabase: boolean;
}

export interface Access {
  /** Any document write allowed by RBAC (legacy summary). */
  portalWrite: boolean;
  portal?: PortalAccess;
  mongo: Capabilities;
}

export interface DatabaseInfo {
  name: string;
  sizeOnDisk: number;
  empty: boolean;
}

export interface CollectionInfo {
  name: string;
  type: string;
  readOnly: boolean;
  options?: Record<string, unknown>;
  access: Access;
}

export type EJSONDocument = Record<string, unknown>;

export interface DocPage {
  documents: EJSONDocument[];
  ids: string[];
  hasMore: boolean;
  truncated: boolean;
  skip: number;
  limit: number;
  elapsedMs: number;
}

export interface DocumentsResponse {
  page: DocPage;
  access?: Access;
  count?: number;
  countCapped?: boolean;
}

export interface SessionSummary {
  handle: string;
  profile: string;
  mongoUser: string;
  authSource: string;
  createdAt: string;
  lastSeen: string;
  expiresAt: string;
  userAgent: string;
  current: boolean;
  tls: boolean;
}

export interface AuditEvent {
  time: string;
  requestId?: string;
  ssoUser: string;
  identity?: IdentitySource;
  portalRole?: string;
  mongoUser?: string;
  profile?: string;
  action: string;
  database?: string;
  collection?: string;
  target?: string;
  outcome: 'success' | 'denied' | 'failure';
  reason?: string;
  id?: string;
  traceId?: string;
  provider?: string;
  method?: string;
  errorClass?: string;
  durationMs?: number;
  count?: number;
  client?: string;
  session?: string;
  pod?: string;
  seq?: number;
  hash?: string;
}

export interface QueryRequest {
  operation: 'find' | 'findOne' | 'countDocuments' | 'aggregate';
  filter?: string;
  projection?: string;
  sort?: string;
  pipeline?: string;
  limit?: number;
  skip?: number;
  maxTimeMS?: number;
}

export interface QueryResponse {
  page?: DocPage;
  count?: number;
  countCapped?: boolean;
}

export interface PolicyStatus {
  source: 'file' | 'config' | 'built-in';
  defaultRole: string;
  loadedAt: string;
  error?: string;
}

export interface RbacRule {
  role: string;
  resource: string;
  action: string;
  object: string;
  effect: 'allow' | 'deny';
}

export interface PermissionsInfo {
  user: string;
  source: IdentitySource;
  subjects: string[];
  roles: string[];
  directRoles: string[];
  defaultRole: string;
  rules: RbacRule[];
  policy: PolicyStatus;
  check?: { resource: string; action: string; object: string; allowed: boolean };
}

export interface StatusInfo {
  auth: AuthOptions;
  profiles: { name: string; displayName: string; health: ProfileHealth }[];
  build: { version: string; commit: string };
  rbac?: PolicyStatus;
  tracing?: boolean;
  tracingDetail?: { enabled: boolean; protocol?: string; endpoint?: string; tls: boolean; sampleRatio: number; source?: string; reason?: string };
  shell?: boolean;
  transfer?: boolean;
  sessions?: { active: number; max: number; registry?: boolean };
  audit?: { persistent: boolean; written: number; dropped: number; lastError?: string };
  store?: { state: string; reason?: string; database?: string };
  pod?: string;
}

/** One independently collected monitoring section. */
export interface MonSection<T> {
  data?: T;
  error?: string;
  code?: string;
}

export interface MonServer {
  host: string;
  version: string;
  process: string;
  uptimeSeconds: number;
  storageEngine: string;
  connections: { current: number; available: number; active: number; totalCreated: number; rejected: number; exhaustHello: number; awaitingTopologyChanges: number };
  network: { bytesIn: number; bytesOut: number; numRequests: number; physicalBytesIn?: number; physicalBytesOut?: number };
  opcounters: Record<'insert' | 'query' | 'update' | 'delete' | 'getmore' | 'command', number>;
  memoryMB: { resident: number; virtual: number };
  cache: { bytesInCache: number; maxBytes: number; dirtyBytes: number };
  activeClients: { readers: number; writers: number; total: number };
  eviction?: {
    applicationThreadPages: number;
    modifiedPages: number;
    unmodifiedPages: number;
    pagesReadIntoCache: number;
    pagesWrittenFromCache: number;
    bytesReadIntoCache: number;
    bytesWrittenFromCache: number;
  };
  tickets?: { readOut: number; readAvailable: number; writeOut: number; writeAvailable: number };
  latency?: Record<'reads' | 'writes' | 'commands' | 'transactions', { latencyMicros: number; ops: number }>;
  cpu?: { user_time_us: number; system_time_us: number; page_faults: number };
  locks?: { globalWaitCount: number; globalWaitMicros: number };
  authentication?: { received: number; successful: number; failed: number; byMechanism: Record<string, { received: number; successful: number }> };
  queue: { readers: number; writers: number; total: number };
  asserts: Record<'regular' | 'warning' | 'msg' | 'user' | 'rollovers', number>;
  transactions: { currentActive: number; currentOpen: number; totalCommitted: number; totalAborted: number };
}

export interface MonHost {
  hostname: string;
  cpuArch: string;
  numCores: number;
  memSizeMB: number;
  memLimitMB: number;
  os: string;
}

export interface MonMember {
  name: string;
  state: string;
  health: number;
  uptimeSeconds: number;
  pingMs: number;
  self: boolean;
  syncSource: string;
  lastHeartbeatMessage: string;
  optimeDate?: string;
  lagSeconds?: number;
  priority?: number;
  votes?: number;
  hidden?: boolean;
  arbiterOnly?: boolean;
}

export interface MonReplicaSet {
  standalone?: boolean;
  set?: string;
  term?: number;
  members?: MonMember[];
  majorityVoteCount?: number;
  writeMajorityCount?: number;
  lastElection?: { date?: string; reason?: string; term?: number; role: 'candidate' | 'participant'; votedForCandidate?: boolean };
}

export interface MonDatabases {
  totalSize: number;
  visibleSize: number;
  databases: DatabaseInfo[];
  stats?: MonDbStats[];
}

export interface MonClientGroup {
  client: string;
  appName: string;
  user: string;
  total: number;
  active: number;
  idle: number;
}

export interface MonOperation {
  opid: unknown;
  op: string;
  ns: string;
  secsRunning: number;
  client: string;
  appName: string;
  user: string;
  waitingForLock: boolean;
  planSummary?: string;
}

export interface MonConnections {
  total: number;
  active: number;
  idle: number;
  internalThreads: number;
  clientGroups: number;
  byClient: MonClientGroup[];
  operations: MonOperation[];
  slowOperations?: number;
}

export interface MonitoringInfo {
  collectedAt: string;
  profile: string;
  tls: boolean;
  session: { pool: { open: number; inUse: number; idle: number }; maxPoolSize: number };
  sections: {
    server?: MonSection<MonServer>;
    host?: MonSection<MonHost>;
    replicaSet?: MonSection<MonReplicaSet>;
    databases?: MonSection<MonDatabases>;
    connections?: MonSection<MonConnections>;
    oplog?: MonSection<MonOplog>;
  };
  alerts?: MonAlert[];
  thresholds?: Record<string, number>;
}

// ---- import / export ----

export type TransferFormat = 'ndjson' | 'json' | 'csv' | 'tsv' | 'bson';

export interface FieldMap {
  column: string;
  field?: string;
  type?: string;
  skip?: boolean;
}

export interface ImportPreview {
  format: TransferFormat;
  gzip: boolean;
  documents: Record<string, unknown>[];
  columns?: string[];
  types?: Record<string, string>;
  errors: { record: number; message: string }[];
  partial: boolean;
}

export interface Job {
  id: string;
  kind: string;
  profile: string;
  database: string;
  collection: string;
  format: string;
  mode: 'insert' | 'upsert';
  dryRun: boolean;
  fileName?: string;
  fileBytes: number;
  sha256: string;
  gzip: boolean;
  state: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
  message?: string;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  read: number;
  inserted: number;
  upserted: number;
  matched: number;
  failed: number;
  processedBytes: number;
  errors: { record: number; code?: number; message: string }[];
}

// ---- operations ----

export interface Operation {
  opid: number | string;
  type: string;
  op: string;
  ns: string;
  active: boolean;
  secsRunning: number;
  client: string;
  appName: string;
  user: string;
  desc: string;
  connectionId?: number;
  waitingForLock: boolean;
  planSummary?: string;
  killPending: boolean;
  slow: boolean;
  portal: boolean;
  internal: boolean;
}

export interface OperationsPage {
  operations: Operation[];
  total: number;
  offset: number;
  limit: number;
  allUsers: boolean;
  slowSeconds: number;
  canKill: boolean;
  note?: string;
}

// ---- audit ----

export interface AuditQuery {
  scope: 'self' | 'all';
  user?: string;
  action?: string;
  outcome?: string;
  profile?: string;
  database?: string;
  collection?: string;
  q?: string;
  from?: string;
  to?: string;
  limit?: number;
}

export interface AuditPage {
  events: AuditEvent[];
  scope: 'self' | 'all';
  durable: boolean;
  note: string;
  next?: { before: string; beforeId: string };
}

// ---- sessions administration ----

export interface SessionMeta {
  handle: string;
  owner: string;
  user: string;
  identity: string;
  provider?: string;
  profile: string;
  mongoUser: string;
  authSource: string;
  mechanism: string;
  pod: string;
  clientIP?: string;
  userAgent?: string;
  tls: boolean;
  createdAt: string;
  lastSeen: string;
  expiresAt: string;
  current: boolean;
  local: boolean;
}

export interface AdminSessions {
  sessions: SessionMeta[];
  source: 'registry' | 'local';
  note: string;
  canRevoke: boolean;
}

// ---- monitoring additions ----

export interface MonAlert {
  severity: 'info' | 'warning' | 'critical';
  section: string;
  message: string;
}

export interface MonOplog {
  available: boolean;
  first?: string;
  last?: string;
  windowSeconds?: number;
  sizeBytes?: number;
  maxSizeBytes?: number;
}

export interface MonDbStats {
  name: string;
  collections: number;
  objects: number;
  dataSize: number;
  storageSize: number;
  indexSize: number;
  indexes: number;
  fsUsedSize: number;
  fsTotalSize: number;
}

export interface IndexUsage {
  name: string;
  host: string;
  ops: number;
  since?: string;
}
