import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';
import os from 'node:os';
import path from 'node:path';

const exec = promisify(execFile);

// Accepts: https://github.com/owner/repo, github.com/owner/repo, owner/repo,
// optional .git suffix, optional /tree/<branch>/... path.
export function parseGithubUrl(input) {
  const s = String(input || '').trim();
  const m = s.match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9_.\-]+)\/([A-Za-z0-9_.\-]+?)(?:\.git)?(?:\/tree\/([^/\s]+))?(?:\/.*)?$/)
    || s.match(/^([A-Za-z0-9_.\-]+)\/([A-Za-z0-9_.\-]+?)(?:\.git)?$/);
  if (!m) return null;
  const [, owner, repo, branch] = m;
  if (owner === '.' || owner === '..' || repo === '.' || repo === '..') return null;
  return { owner, repo, branch: branch || null, cloneUrl: `https://github.com/${owner}/${repo}.git`, webUrl: `https://github.com/${owner}/${repo}` };
}

let gitAvailable = null;
export async function hasGit() {
  if (gitAvailable !== null) return gitAvailable;
  try { await exec('git', ['--version']); gitAvailable = true; } catch { gitAvailable = false; }
  return gitAvailable;
}

function httpError(msg, status) { return Object.assign(new Error(msg), { status }); }

// ---- Strategy 1: git shallow clone (fast, gives us the commit hash) ----
async function gitClone({ cloneUrl, branch }, dir, timeoutMs) {
  const args = ['clone', '--depth', '1', '--single-branch', '--no-tags', '--quiet'];
  if (branch) args.push('--branch', branch);
  args.push(cloneUrl, dir);
  try {
    await exec('git', args, {
      timeout: timeoutMs,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0' }, // never hang on a password prompt
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch (err) {
    const msg = (err.stderr || err.message || '').toString();
    if (/not found|could not read|authentication|terminal prompts disabled/i.test(msg)) {
      throw httpError('Repository not found or not public. Only public GitHub repositories can be scanned.', 404);
    }
    if (/Remote branch .* not found/i.test(msg)) throw httpError(`Branch "${branch}" not found.`, 404);
    if (err.killed || /timed out/i.test(msg)) throw httpError('Clone timed out — the repository may be too large for a quick scan.', 504);
    throw httpError('Clone failed: ' + msg.split('\n')[0], 502);
  }
  return { commit: await headCommit(dir) };
}

// ---- Strategy 2: download GitHub's tarball and extract with tar (no git needed) ----
// `tar` ships with Windows 10+, macOS and every Linux.
async function tarballDownload({ owner, repo, branch }, dir, timeoutMs) {
  const ref = branch || 'HEAD';
  const url = `https://codeload.github.com/${owner}/${repo}/tar.gz/${encodeURIComponent(ref)}`;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  const archive = path.join(dir, 'repo.tar.gz');
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: 'follow', headers: { 'user-agent': 'repo-secret-sweeper' } });
    if (res.status === 404) throw httpError(branch ? `Repository or branch "${branch}" not found (or not public).` : 'Repository not found or not public. Only public GitHub repositories can be scanned.', 404);
    if (!res.ok) throw httpError(`GitHub returned ${res.status} while downloading the repository.`, 502);
    await pipeline(Readable.fromWeb(res.body), createWriteStream(archive));
  } catch (err) {
    if (err.status) throw err;
    if (err.name === 'AbortError') throw httpError('Download timed out — the repository may be too large for a quick scan.', 504);
    throw httpError('Download failed: ' + err.message, 502);
  } finally {
    clearTimeout(t);
  }

  // The archive's top-level folder is "<repo>-<sha>/" for HEAD downloads, so the commit
  // can be recovered from the listing. Optional: a failure here just leaves commit null.
  let commit = null;
  try {
    const { stdout } = await exec('tar', ['-tzf', archive], { maxBuffer: 50 * 1024 * 1024 });
    const top = (stdout.split('\n')[0] || '').replace(/\/.*$/, '');
    const m = top.match(/-([0-9a-f]{7,40})$/i);
    if (m) commit = m[1].slice(0, 7);
  } catch { /* optional */ }

  const out = path.join(dir, 'src');
  await fs.mkdir(out);
  try {
    // --strip-components=1 drops that top folder.
    await exec('tar', ['-xzf', archive, '-C', out, '--strip-components=1'], { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 });
  } catch (err) {
    throw httpError('Could not extract the repository archive (is `tar` available on this machine?): ' + (err.stderr || err.message).toString().split('\n')[0], 500);
  }
  await fs.rm(archive, { force: true });
  return { root: out, commit };
}

export async function shallowClone(parsed, { timeoutMs = 90_000 } = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sweeper-'));
  try {
    if (await hasGit()) {
      const { commit } = await gitClone(parsed, dir, timeoutMs);
      return { dir, root: dir, commit, method: 'git' };
    }
    const { root, commit } = await tarballDownload(parsed, dir, timeoutMs);
    return { dir, root, commit, method: 'tarball' };
  } catch (err) {
    await fs.rm(dir, { recursive: true, force: true });
    throw err;
  }
}

export async function headCommit(dir) {
  try {
    const { stdout } = await exec('git', ['-C', dir, 'rev-parse', '--short', 'HEAD']);
    return stdout.trim();
  } catch { return null; }
}

export async function cleanup(dir) {
  if (dir) await fs.rm(dir, { recursive: true, force: true }).catch(() => {});
}
