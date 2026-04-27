import type { NormalizedFindings, PostureSnapshot } from './types';

const REPO = 'Scorp10N/security-data';
const API = 'https://api.github.com';
const CACHE_TTL_MS = 5 * 60 * 1000;

function cacheKey(path: string): string {
  return `gh:${path}`;
}

function cacheGet<T>(path: string): T | null {
  const raw = sessionStorage.getItem(cacheKey(path));
  if (!raw) return null;
  const { data, ts } = JSON.parse(raw) as { data: T; ts: number };
  if (Date.now() - ts > CACHE_TTL_MS) {
    sessionStorage.removeItem(cacheKey(path));
    return null;
  }
  return data;
}

function cacheSet<T>(path: string, data: T): void {
  sessionStorage.setItem(cacheKey(path), JSON.stringify({ data, ts: Date.now() }));
}

async function ghFetch<T>(token: string, path: string, raw = true): Promise<T> {
  const cached = cacheGet<T>(path);
  if (cached) return cached;

  const res = await fetch(`${API}/repos/${REPO}/contents/${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: raw
        ? 'application/vnd.github.raw+json'
        : 'application/vnd.github+json',
    },
  });

  if (res.status === 401 || res.status === 403) throw new Error('auth');
  if (res.status === 404) throw new Error('not_found');
  if (!res.ok) throw new Error(`github_${res.status}`);

  const data = raw ? await res.json() : await res.json();
  cacheSet(path, data);
  return data as T;
}

export async function fetchPosture(token: string): Promise<PostureSnapshot> {
  return ghFetch<PostureSnapshot>(token, 'posture/snapshot-latest.json');
}

export async function fetchFindings(
  token: string,
  repoSlug: string
): Promise<NormalizedFindings> {
  return ghFetch<NormalizedFindings>(
    token,
    `findings/${repoSlug}/latest/normalized.json`
  );
}

export async function fetchPostureHistory(
  token: string
): Promise<PostureSnapshot[]> {
  const entries = await ghFetch<Array<{ name: string }>>(
    token,
    'posture',
    false
  );
  const snapshots = entries
    .map((e) => e.name)
    .filter((n) => n.startsWith('snapshot-') && n.endsWith('.json') && n !== 'snapshot-latest.json')
    .sort()
    .slice(-30);

  return Promise.all(
    snapshots.map((name) =>
      ghFetch<PostureSnapshot>(token, `posture/${name}`)
    )
  );
}
