import fs from 'node:fs/promises';
import path from 'node:path';
import { RULES, SENSITIVE_FILES, PLACEHOLDER_HINTS, SEVERITY_WEIGHT, ROTATION_STEPS } from './rules.js';

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', 'out', '.next', '.nuxt', 'vendor', '__pycache__',
  '.venv', 'venv', 'target', 'coverage', '.cache', '.idea', '.vscode', 'bower_components',
]);

const SKIP_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg', '.bmp', '.tiff',
  '.mp3', '.mp4', '.wav', '.mov', '.avi', '.webm', '.ogg',
  '.zip', '.gz', '.tar', '.rar', '.7z', '.bz2', '.xz',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.class', '.jar', '.pyc', '.o', '.a',
  '.lock', '.map', '.min.js', '.min.css',
]);

const SKIP_FILES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'Cargo.lock', 'poetry.lock', 'composer.lock', 'Gemfile.lock',
]);

const MAX_FILE_BYTES = 1_000_000; // 1 MB — anything larger is almost never hand-written source
const MAX_FILES = 5000;
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// ---------- helpers ----------

export function shannonEntropy(str) {
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function mask(secret) {
  if (!secret) return '';
  if (secret.length <= 8) return secret[0] + '*'.repeat(secret.length - 1);
  const head = secret.slice(0, 4);
  const tail = secret.slice(-3);
  return `${head}${'*'.repeat(Math.min(secret.length - 7, 20))}${tail}`;
}

// `strict` = the value matched a provider-specific format (e.g. "sk_live_…"). Those are
// real-shaped by construction, so only structural signs of a placeholder count:
// interpolation, env lookups, angle-bracket templates, or obvious "xxxx"/"your_" text.
// Credentials that appear verbatim in vendor documentation. Seeing them means someone
// copied a doc snippet, not that a real account is exposed.
const KNOWN_EXAMPLES = new Set([
  'AKIAIOSFODNN7EXAMPLE',
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  'AKIAI44QH8DHBEXAMPLE',
  'je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY',
  'sk_test_' + '4eC39HqLyjWDarjtT1zdp7dc', // Stripe docs (split so GitHub push protection ignores it)
  'sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc',
]);

export function looksLikePlaceholder(value, line, strict = false) {
  const v = value.toLowerCase();
  const l = line.toLowerCase();
  if (KNOWN_EXAMPLES.has(value)) return true;
  if (/localhost|127\.0\.0\.1|0\.0\.0\.0|:password@|:pass@|:secret@|user:pass/.test(v)) return true; // local / doc URLs
  if (/\$\{?[A-Za-z_]+\}?/.test(value)) return true; // ${VAR} / $VAR interpolation
  if (/process\.env|os\.environ|getenv|import\.meta\.env|secrets\.|vault/.test(l)) return true;
  if (/^(<|\[|\{).*(>|\]|\})$/.test(value)) return true; // <token> / [token]
  if (/xxxx|\*\*\*\*|your[_-]|<your|changeme|change_me|placeholder|redacted/.test(v)) return true;
  if (strict) return false;
  if (PLACEHOLDER_HINTS.some((h) => v.includes(h))) return true;
  if (/^(.)\1{5,}$/.test(value)) return true; // aaaaaaaa
  if (/^[0-9]+$/.test(value) && value.length < 12) return true;
  return false;
}

// Secrets in tests, fixtures, docs and examples are usually deliberate fakes.
// They still get reported (a real key in a test is still a real key) but one level lower.
const TEST_OR_DOCS = /(^|\/)(tests?|__tests__|__mocks__|spec|specs|fixtures?|examples?|samples?|docs?|e2e|cypress|storybook|\.storybook)(\/|$)|(^|\/)(readme|changelog|contributing)[^/]*$|\.(md|mdx|rst|txt)$|\.(test|spec|stories)\.[jt]sx?$/i;

export function isTestOrDocs(rel) { return TEST_OR_DOCS.test(rel); }

const DOWNGRADE = { critical: 'high', high: 'medium', medium: 'low', low: 'low' };

function isBinaryBuffer(buf) {
  const len = Math.min(buf.length, 512);
  for (let i = 0; i < len; i++) if (buf[i] === 0) return true;
  return false;
}

function shouldSkipFile(rel) {
  const base = path.basename(rel);
  if (SKIP_FILES.has(base)) return true;
  const lower = base.toLowerCase();
  for (const ext of SKIP_EXT) if (lower.endsWith(ext)) return true;
  return false;
}

async function* walk(root) {
  const stack = [root];
  let count = 0;
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) stack.push(full);
      } else if (e.isFile()) {
        if (++count > MAX_FILES) return;
        yield full;
      }
    }
  }
}

// ---------- core scan ----------

// ±N lines of context around a finding, with every known secret value masked.
// Kept on the finding for display after the clone is deleted.
function snippetAround(lines, lineNo, secrets, radius = 4) {
  const start = Math.max(0, lineNo - 1 - radius);
  const end = Math.min(lines.length, lineNo + radius);
  return lines.slice(start, end).map((text, i) => {
    let t = text.length > 300 ? text.slice(0, 300) + '…' : text;
    for (const s of secrets) if (s && t.includes(s)) t = t.split(s).join(mask(s));
    return { n: start + i + 1, text: t };
  });
}

function scanLine(line, lineNo, rel, findings, seen, fileSecrets) {
  if (line.length > 5000) return; // minified / data blobs

  const hits = []; // { rule, secret, index, specific }

  for (const rule of RULES) {
    rule.regex.lastIndex = 0;
    let m;
    while ((m = rule.regex.exec(line)) !== null) {
      const secret = m[1] ?? m[0];
      if (rule.verify && !rule.verify(secret)) continue;
      hits.push({ rule, secret, index: m.index, specific: rule.provider !== 'generic' });
    }
  }

  // Entropy pass: long, random-looking tokens assigned to something credential-ish.
  const assign = /\b([A-Za-z_][A-Za-z0-9_\-]{2,40})\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{24,})["']/g;
  let m;
  while ((m = assign.exec(line)) !== null) {
    const [, name, value] = m;
    if (!/key|secret|token|pass|auth|cred|api|salt|sign/i.test(name)) continue;
    const h = shannonEntropy(value);
    const threshold = /^[0-9a-fA-F]+$/.test(value) ? 3.0 : 4.3;
    if (h < threshold) continue;
    hits.push({
      rule: { id: 'high-entropy-string', name: `High-entropy value assigned to "${name}"`, provider: 'generic', severity: 'medium' },
      secret: value, index: m.index, specific: false, entropy: Number(h.toFixed(2)), detector: 'entropy',
    });
  }

  // A generic / entropy hit whose value overlaps a provider-specific hit is noise: drop it.
  const specificSecrets = hits.filter((h) => h.specific).map((h) => h.secret);
  const kept = hits.filter((h) => h.specific || !specificSecrets.some((s) => s.includes(h.secret) || h.secret.includes(s)));
  for (const h of hits) fileSecrets.add(h.secret);

  for (const h of kept) {
    const key = `${h.rule.id}:${h.secret}`;
    if (seen.has(key)) {
      findings.find((f) => f.key === key)?.occurrences.push({ file: rel, line: lineNo });
      continue;
    }
    seen.add(key);
    const placeholder = looksLikePlaceholder(h.secret, line, h.specific);
    const testOrDocs = isTestOrDocs(rel);
    let severity = placeholder ? 'low' : h.rule.severity;
    if (testOrDocs && !placeholder) severity = DOWNGRADE[severity];
    findings.push({
      key,
      ruleId: h.rule.id,
      name: h.rule.name,
      provider: h.rule.provider,
      severity,
      placeholder,
      testOrDocs,
      file: rel,
      line: lineNo,
      column: h.index + 1,
      masked: mask(h.secret),
      context: line.trim().slice(0, 200),
      occurrences: [],
      detector: h.detector || 'pattern',
      ...(h.entropy !== undefined && { entropy: h.entropy }),
    });
  }
}

export async function scanDirectory(root) {
  const findings = [];
  const seen = new Set();
  let filesScanned = 0;
  let filesSkipped = 0;
  let bytesScanned = 0;

  for await (const full of walk(root)) {
    const rel = path.relative(root, full).split(path.sep).join('/');

    // 1. Sensitive file names
    for (const sf of SENSITIVE_FILES) {
      if (sf.pattern.test(rel) && !(sf.exclude && sf.exclude.test(rel))) {
        const testOrDocs = isTestOrDocs(rel);
        findings.push({
          key: `file:${rel}`,
          ruleId: 'sensitive-file',
          name: sf.name,
          provider: sf.provider,
          severity: testOrDocs ? DOWNGRADE[sf.severity] : sf.severity,
          placeholder: false,
          testOrDocs,
          file: rel,
          line: 0,
          column: 0,
          masked: '',
          context: `File should not be in version control: ${rel}`,
          occurrences: [],
          detector: 'filename',
        });
      }
    }

    if (shouldSkipFile(rel)) { filesSkipped++; continue; }

    let stat;
    try { stat = await fs.stat(full); } catch { continue; }
    if (stat.size > MAX_FILE_BYTES || stat.size === 0) { filesSkipped++; continue; }

    const buf = await fs.readFile(full);
    if (isBinaryBuffer(buf)) { filesSkipped++; continue; }

    filesScanned++;
    bytesScanned += buf.length;
    const text = buf.toString('utf8');
    const lines = text.split(/\r?\n/);
    const firstIdx = findings.length;
    const fileSecrets = new Set();
    for (let i = 0; i < lines.length; i++) scanLine(lines[i], i + 1, rel, findings, seen, fileSecrets);
    // Attach context snippets now that every secret in this file is known, so none leaks unmasked.
    for (let i = firstIdx; i < findings.length; i++) {
      const f = findings[i];
      if (f.line === 0) continue;
      for (const s of fileSecrets) if (s && f.context.includes(s)) f.context = f.context.split(s).join(mask(s));
      if (f.ruleId === 'private-key') {
        // The pattern only matches the header; everything after it on the line (and the
        // following lines) is key material. Never show any of it.
        const i = f.context.indexOf(f.masked);
        f.context = (i >= 0 ? f.context.slice(0, i) : '') + '-----BEGIN … PRIVATE KEY----- [key material hidden]';
        f.snippet = [];
      } else {
        f.snippet = snippetAround(lines, f.line, fileSecrets);
      }
    }
  }

  findings.sort((a, b) =>
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);

  for (const f of findings) delete f.key;

  return { findings, stats: { filesScanned, filesSkipped, bytesScanned } };
}

// ---------- reporting ----------

export function summarize(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity]++;
  // 100 = clean; one critical finding alone drops you to 75. Placeholders cost nothing;
  // findings inside tests/docs (already downgraded one level) count half.
  const raw = findings.reduce((s, f) => {
    if (f.placeholder) return s;
    return s + SEVERITY_WEIGHT[f.severity] * (f.testOrDocs ? 0.5 : 1);
  }, 0);
  const score = Math.max(0, Math.round(100 - raw));
  let grade = 'A';
  if (score < 95) grade = 'B';
  if (score < 80) grade = 'C';
  if (score < 60) grade = 'D';
  if (score < 40) grade = 'F';
  return { counts, score, grade, total: findings.length };
}

export function buildGitignore(findings) {
  const lines = new Set(['# --- added by Repo Secret Sweeper ---']);
  const has = (id) => findings.some((f) => f.ruleId === id || f.provider === id);
  lines.add('.env');
  lines.add('.env.*');
  lines.add('!.env.example');
  if (has('private-key')) {
    ['*.pem', '*.key', '*.p12', '*.pfx', '*.jks', 'id_rsa', 'id_ed25519'].forEach((l) => lines.add(l));
  }
  if (has('google')) {
    lines.add('*service-account*.json');
    lines.add('firebase-adminsdk*.json');
  }
  if (has('aws')) lines.add('.aws/');
  if (has('npm')) lines.add('.npmrc');
  if (findings.some((f) => /credentials|secrets?\./i.test(f.file))) {
    lines.add('credentials.json');
    lines.add('secrets.json');
    lines.add('secrets.yaml');
  }
  return Array.from(lines).join('\n') + '\n';
}

export function buildRotationChecklist(findings) {
  const providers = new Map();
  for (const f of findings) {
    if (f.placeholder) continue;
    if (!providers.has(f.provider)) providers.set(f.provider, []);
    providers.get(f.provider).push(f);
  }
  const checklist = [];
  for (const [provider, items] of providers) {
    const info = ROTATION_STEPS[provider] ?? ROTATION_STEPS.generic;
    checklist.push({
      provider,
      label: info.label,
      docs: info.docs,
      steps: info.steps,
      findings: items.map((f) => ({ name: f.name, file: f.file, line: f.line, severity: f.severity })),
    });
  }
  checklist.sort((a, b) => {
    const worst = (c) => Math.min(...c.findings.map((f) => SEVERITY_ORDER[f.severity]));
    return worst(a) - worst(b);
  });
  if (findings.some((f) => !f.placeholder)) {
    checklist.push({
      provider: 'history',
      label: 'Git history',
      docs: 'https://docs.github.com/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository',
      steps: [
        'Deleting the secret in a new commit is not enough — it stays in history. Rewrite with `git filter-repo` or BFG Repo-Cleaner, then force-push.',
        'Ask collaborators to re-clone; old clones still contain the secret.',
        'If the repo is public, assume the secret has already been scraped — rotation is mandatory, history rewrite is cleanup.',
      ],
      findings: [],
    });
  }
  return checklist;
}
