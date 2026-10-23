// Recently visited namespaces, for the command palette. Like the theme, this
// is a per-browser convenience: only database and collection names are kept
// (never credentials or documents), and storage failures are ignored.

const KEY = 'mongo-portal-recent';
const MAX = 8;

export interface RecentItem {
  db: string;
  coll?: string;
}

function read(): RecentItem[] {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? '[]') as unknown;
    if (!Array.isArray(v)) return [];
    return v
      .filter((x): x is RecentItem => typeof x === 'object' && x !== null && typeof (x as RecentItem).db === 'string')
      .map((x) => ({ db: x.db, coll: typeof x.coll === 'string' ? x.coll : undefined }))
      .slice(0, MAX);
  } catch {
    return [];
  }
}

export function recentItems(): RecentItem[] {
  return read();
}

export function rememberRecent(item: RecentItem) {
  const list = [item, ...read().filter((x) => x.db !== item.db || x.coll !== item.coll)].slice(0, MAX);
  try {
    localStorage.setItem(KEY, JSON.stringify(list));
  } catch {
    // storage unavailable; ignore
  }
}

export function clearRecent() {
  try {
    localStorage.removeItem(KEY);
  } catch {
    // ignore
  }
}

/** Remembered connection profile name (not credentials). */
const PROFILE_KEY = 'mongo-portal-profile';

export function lastProfile(): string | undefined {
  try {
    return localStorage.getItem(PROFILE_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

export function rememberProfile(name: string) {
  try {
    localStorage.setItem(PROFILE_KEY, name);
  } catch {
    // ignore
  }
}
