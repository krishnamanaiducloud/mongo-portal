import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, enc, nsPath, setCsrfToken } from './client';
import type {
  Access,
  AuditEvent,
  CollectionInfo,
  DatabaseInfo,
  DocumentsResponse,
  EJSONDocument,
  Me,
  MonitoringInfo,
  PermissionsInfo,
  Profile,
  QueryRequest,
  QueryResponse,
  SessionInfo,
  SessionSummary,
  StatusInfo,
} from './types';

export const keys = {
  me: ['me'] as const,
  profiles: ['profiles'] as const,
  session: ['session'] as const,
  sessions: ['sessions'] as const,
  databases: ['databases'] as const,
  dbStats: (db: string) => ['dbStats', db] as const,
  collections: (db: string) => ['collections', db] as const,
  collStats: (db: string, coll: string) => ['collStats', db, coll] as const,
  documents: (db: string, coll: string) => ['documents', db, coll] as const,
  indexes: (db: string, coll: string) => ['indexes', db, coll] as const,
  server: ['server'] as const,
  monitoring: ['monitoring'] as const,
  audit: (scope: string) => ['audit', scope] as const,
  status: ['status'] as const,
  permissions: ['permissions'] as const,
};

export function useMe() {
  return useQuery({
    queryKey: keys.me,
    queryFn: async () => {
      const me = await api<Me>('/me');
      setCsrfToken(me.csrfToken);
      return me;
    },
    retry: false,
    staleTime: 60_000,
  });
}

export function useProfiles() {
  return useQuery({
    queryKey: keys.profiles,
    queryFn: () => api<{ profiles: Profile[] }>('/profiles').then((r) => r.profiles),
    staleTime: 5 * 60_000,
  });
}

export function useSession(enabled = true) {
  return useQuery({
    queryKey: keys.session,
    queryFn: async () => {
      const s = await api<SessionInfo>('/session');
      setCsrfToken(s.csrfToken);
      return s;
    },
    retry: false,
    enabled,
    refetchInterval: 60_000,
  });
}

export interface LoginInput {
  profile: string;
  username: string;
  password: string;
  authSource: string;
  mechanism: string;
}

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: LoginInput) => api<SessionInfo>('/session', { method: 'POST', body: input }),
    onSuccess: (s) => {
      setCsrfToken(s.csrfToken);
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== 'me' && q.queryKey[0] !== 'profiles' });
      qc.setQueryData(keys.session, s);
      // Without SSO the MongoDB user becomes the identity: refresh roles.
      void qc.invalidateQueries({ queryKey: keys.me });
    },
  });
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api<{ loggedOut: boolean; ssoLogoutURL: string }>('/session', { method: 'DELETE' }),
    onSettled: () => {
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== 'me' && q.queryKey[0] !== 'profiles' });
      void qc.invalidateQueries({ queryKey: keys.me });
    },
  });
}

export function useSessions() {
  return useQuery({
    queryKey: keys.sessions,
    queryFn: () => api<{ sessions: SessionSummary[]; note: string }>('/sessions'),
  });
}

export function useTerminateSession() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (handle: string) => api(`/sessions/${enc(handle)}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.sessions }),
  });
}

export function useDatabases() {
  return useQuery({
    queryKey: keys.databases,
    queryFn: () => api<{ databases: DatabaseInfo[]; source: string; totalSize?: number; visibleSize?: number }>('/databases'),
  });
}

export function useDatabaseStats(db: string) {
  return useQuery({
    queryKey: keys.dbStats(db),
    queryFn: () => api<{ stats: Record<string, unknown>; access: Access }>(`${nsPath(db)}/stats`),
    retry: false,
  });
}

export function useCollections(db: string | undefined) {
  return useQuery({
    queryKey: keys.collections(db ?? ''),
    queryFn: () => api<{ collections: CollectionInfo[]; access: Access }>(`${nsPath(db!)}/collections`),
    enabled: !!db,
  });
}

export function useCollectionStats(db: string, coll: string) {
  return useQuery({
    queryKey: keys.collStats(db, coll),
    queryFn: () => api<{ stats: Record<string, unknown>; limited?: boolean; access: Access }>(`${nsPath(db, coll)}/stats`),
    retry: false,
  });
}

export interface FindParams {
  filter: string;
  projection: string;
  sort: string;
  skip: number;
  limit: number;
}

export function useDocuments(db: string, coll: string, p: FindParams) {
  return useQuery({
    queryKey: [...keys.documents(db, coll), p],
    queryFn: ({ signal }) => {
      const q = new URLSearchParams({ skip: String(p.skip), limit: String(p.limit), count: 'true' });
      if (p.filter.trim()) q.set('filter', p.filter);
      if (p.projection.trim()) q.set('projection', p.projection);
      if (p.sort.trim()) q.set('sort', p.sort);
      return api<DocumentsResponse>(`${nsPath(db, coll)}/documents?${q}`, { signal });
    },
    placeholderData: keepPreviousData,
    retry: false,
  });
}

export function fetchDocument(db: string, coll: string, id: string, format: 'canonical' | 'relaxed') {
  return api<{ document: EJSONDocument; id: string }>(`${nsPath(db, coll)}/documents/${enc(id)}?format=${format}`);
}

function useInvalidateNs(db: string, coll: string) {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: keys.documents(db, coll) });
    void qc.invalidateQueries({ queryKey: keys.collStats(db, coll) });
  };
}

export function useInsertDocument(db: string, coll: string) {
  const inv = useInvalidateNs(db, coll);
  return useMutation({
    mutationFn: (document: string) => api<{ id: string }>(`${nsPath(db, coll)}/documents`, { method: 'POST', body: { document } }),
    onSuccess: inv,
  });
}

export function useReplaceDocument(db: string, coll: string) {
  const inv = useInvalidateNs(db, coll);
  return useMutation({
    mutationFn: ({ id, document }: { id: string; document: string }) =>
      api(`${nsPath(db, coll)}/documents/${enc(id)}`, { method: 'PUT', body: { document } }),
    onSuccess: inv,
  });
}

export function useDeleteDocument(db: string, coll: string) {
  const inv = useInvalidateNs(db, coll);
  return useMutation({
    mutationFn: (id: string) =>
      api(`${nsPath(db, coll)}/documents/${enc(id)}`, { method: 'DELETE', headers: { 'X-Confirm': 'delete' } }),
    onSuccess: inv,
  });
}

export function useRunQuery(db: string, coll: string) {
  return useMutation({
    mutationFn: (q: QueryRequest) => api<QueryResponse>(`${nsPath(db, coll)}/query`, { method: 'POST', body: q }),
  });
}

export function useIndexes(db: string, coll: string) {
  return useQuery({
    queryKey: keys.indexes(db, coll),
    queryFn: () => api<{ indexes: Record<string, unknown>[]; access: Access }>(`${nsPath(db, coll)}/indexes`),
    retry: false,
  });
}

export function useCreateIndex(db: string, coll: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { keys: string; options: string }) =>
      api<{ name: string }>(`${nsPath(db, coll)}/indexes`, { method: 'POST', body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.indexes(db, coll) }),
  });
}

export function useDropIndex(db: string, coll: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      api(`${nsPath(db, coll)}/indexes/${enc(name)}`, { method: 'DELETE', headers: { 'X-Confirm': name } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.indexes(db, coll) }),
  });
}

export function useCreateCollection(db: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ database, name }: { database?: string; name: string }) =>
      api(`${nsPath(database ?? db)}/collections`, { method: 'POST', body: { name } }),
    onSuccess: (_d, v) => {
      void qc.invalidateQueries({ queryKey: keys.collections(v.database ?? db) });
      void qc.invalidateQueries({ queryKey: keys.databases });
    },
  });
}

export function useDropCollection(db: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      api(`${nsPath(db, name)}`, { method: 'DELETE', headers: { 'X-Confirm': name } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.collections(db) });
      void qc.invalidateQueries({ queryKey: keys.databases });
    },
  });
}

export function useStatus(enabled = true) {
  return useQuery({
    queryKey: keys.status,
    queryFn: () => api<StatusInfo>('/status'),
    refetchInterval: 30_000,
    enabled,
  });
}

export interface AccessCheck {
  resource: string;
  action: string;
  object: string;
}

export function usePermissions(check?: AccessCheck) {
  return useQuery({
    queryKey: [...keys.permissions, check ?? null],
    queryFn: () => {
      const q = check ? `?${new URLSearchParams({ resource: check.resource, action: check.action, object: check.object })}` : '';
      return api<PermissionsInfo>(`/permissions${q}`);
    },
    placeholderData: keepPreviousData,
  });
}

/** Ends the portal sign-in completely (MongoDB session and OpenShift sign-in). */
export function useSignOut() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api<{ signedOut: boolean; ssoLogoutURL: string }>('/auth/logout', { method: 'POST' }),
    onSettled: () => {
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== 'me' });
      void qc.invalidateQueries({ queryKey: keys.me });
    },
  });
}

export function useServerInfo() {
  return useQuery({
    queryKey: keys.server,
    queryFn: () => api<{ server: Record<string, unknown>; tls: boolean; profile: string }>('/server'),
  });
}

/** Live monitoring; polls while the page is visible. */
export function useMonitoring(intervalMs: number | false) {
  return useQuery({
    queryKey: keys.monitoring,
    queryFn: () => api<MonitoringInfo>('/monitoring'),
    refetchInterval: intervalMs,
    refetchIntervalInBackground: false,
    placeholderData: keepPreviousData,
  });
}

export function useAudit(scope: 'self' | 'all') {
  return useQuery({
    queryKey: keys.audit(scope),
    queryFn: () => api<{ events: AuditEvent[]; scope: string; note: string }>(`/audit?scope=${scope}&limit=300`),
    refetchInterval: 30_000,
  });
}
