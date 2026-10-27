import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import path from 'node:path';
import { existsSync } from 'node:fs';
import { execFile as execFileCb } from 'node:child_process';
import { promisify } from 'node:util';
const execFile = promisify(execFileCb);
import { fileURLToPath } from 'node:url';
import { parseGithubUrl, shallowClone, cleanup, hasGit } from './github.js';
import { scanDirectory, summarize, buildGitignore, buildRotationChecklist } from './scanner.js';
import { initStore, storeMode, saveScan, listScans, getScan } from './store.js';
import { RULES, SENSITIVE_FILES } from './rules.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
// The demo repo ships as a tarball (its fake keys would otherwise trip GitHub push
// protection) and is unpacked next to it on first start.
const DEMO_ARCHIVE = path.join(ROOT, 'demo-leaky-repo.tar.gz');
const DEMO_DIR = path.join(ROOT, 'demo-leaky-repo');
async function ensureDemoRepo() {
  if (existsSync(path.join(DEMO_DIR, 'src'))) return;
  if (!existsSync(DEMO_ARCHIVE)) { console.warn('[demo] demo-leaky-repo.tar.gz missing — demo scan disabled'); return; }
  await execFile('tar', ['-xzf', DEMO_ARCHIVE, '-C', ROOT]);
  console.log('[demo] unpacked demo-leaky-repo');
}
const CLIENT_DIST = path.join(ROOT, 'client', 'dist');

const app = express();
app.use(cors());
app.use(express.json({ limit: '100kb' }));

// Very small in-process rate limit: one scan per IP at a time, max N per minute.
const inFlight = new Set();
const recent = new Map();
const PER_MINUTE = Number(process.env.SCANS_PER_MINUTE || 6);
function rateLimited(ip) {
  const now = Date.now();
  const arr = (recent.get(ip) || []).filter((t) => now - t < 60_000);
  recent.set(ip, arr);
  if (arr.length >= PER_MINUTE) return true;
  arr.push(now);
  return false;
}

app.get('/api/health', async (_req, res) => res.json({
  ok: true, store: storeMode(), rules: RULES.length + SENSITIVE_FILES.length, fetch: (await hasGit()) ? 'git' : 'tarball',
}));

app.get('/api/rules', (_req, res) => {
  res.json({
    patterns: RULES.map(({ id, name, provider, severity }) => ({ id, name, provider, severity })),
    files: SENSITIVE_FILES.map(({ name, severity, provider }) => ({ name, severity, provider })),
  });
});

app.post('/api/scan', async (req, res) => {
  const ip = req.ip;
  if (inFlight.has(ip)) return res.status(429).json({ error: 'A scan is already running for you — wait for it to finish.' });
  if (rateLimited(ip)) return res.status(429).json({ error: `Rate limit: max ${PER_MINUTE} scans per minute.` });

  const { repoUrl, demo } = req.body || {};
  let dir = null;
  let scanRoot = null;
  let meta;
  const started = Date.now();
  inFlight.add(ip);
  try {
    if (demo) {
      dir = DEMO_DIR;
      scanRoot = DEMO_DIR;
      meta = { repo: 'demo/leaky-repo', webUrl: null, branch: 'main', commit: 'demo' };
    } else {
      const parsed = parseGithubUrl(repoUrl);
      if (!parsed) return res.status(400).json({ error: 'Enter a public GitHub repository URL like https://github.com/owner/repo' });
      const got = await shallowClone(parsed);
      dir = got.dir;
      scanRoot = got.root;
      meta = { repo: `${parsed.owner}/${parsed.repo}`, webUrl: parsed.webUrl, branch: parsed.branch || 'default', commit: got.commit, method: got.method };
    }

    const { findings, stats } = await scanDirectory(scanRoot);
    const summary = summarize(findings);
    const gitignore = buildGitignore(findings);
    const rotation = buildRotationChecklist(findings);

    const saved = await saveScan({
      ...meta, ...summary, stats, durationMs: Date.now() - started, findings, gitignore, rotation,
    });
    res.json(saved);
  } catch (err) {
    console.error('[scan]', err.message);
    res.status(err.status || 500).json({ error: err.message || 'Scan failed' });
  } finally {
    inFlight.delete(ip);
    if (dir && dir !== DEMO_DIR) await cleanup(dir);
  }
});

app.get('/api/scans', async (_req, res) => {
  res.json(await listScans(20));
});

app.get('/api/scans/:id', async (req, res) => {
  const scan = await getScan(req.params.id);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  res.json(scan);
});

// Serve the built React app in production (single-service deploy).
app.use(express.static(CLIENT_DIST));
app.get(/^(?!\/api).*/, (_req, res, next) => {
  res.sendFile(path.join(CLIENT_DIST, 'index.html'), (err) => err && next());
});

const PORT = process.env.PORT || 4000;
Promise.all([initStore(), ensureDemoRepo().catch((e) => console.warn('[demo]', e.message))]).then(() => {
  app.listen(PORT, () => console.log(`Repo Secret Sweeper API on http://localhost:${PORT} (history: ${storeMode()})`));
});
