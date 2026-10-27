const BASE = import.meta.env.VITE_API_URL || '';

async function request(path, options = {}) {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

export const api = {
  health: () => request('/api/health'),
  scan: (repoUrl) => request('/api/scan', { method: 'POST', body: JSON.stringify({ repoUrl }) }),
  scanDemo: () => request('/api/scan', { method: 'POST', body: JSON.stringify({ demo: true }) }),
  history: () => request('/api/scans'),
  getScan: (id) => request(`/api/scans/${id}`),
  rules: () => request('/api/rules'),
};
