// Theme preference (light/dark) is a non-sensitive UI preference kept in
// browser storage, like the recent namespaces and last profile (lib/recent).
// Credentials, tokens and documents are never stored in the browser.
export type Theme = 'light' | 'dark';

const KEY = 'mongo-portal-theme';
const DARK_CLASS = 'pf-v6-theme-dark';

export function currentTheme(): Theme {
  return document.documentElement.classList.contains(DARK_CLASS) ? 'dark' : 'light';
}

export function applyTheme(t: Theme) {
  document.documentElement.classList.toggle(DARK_CLASS, t === 'dark');
  try {
    localStorage.setItem(KEY, t);
  } catch {
    // storage unavailable (private mode); ignore
  }
}

export function initTheme() {
  let t: Theme | null = null;
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'light' || v === 'dark') t = v;
  } catch {
    t = null;
  }
  if (!t) t = window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.classList.toggle(DARK_CLASS, t === 'dark');
}
