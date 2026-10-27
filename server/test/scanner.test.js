import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { scanDirectory, summarize, shannonEntropy, mask, looksLikePlaceholder } from '../src/scanner.js';
import { parseGithubUrl } from '../src/github.js';

async function tmpRepo(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sweeper-test-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, content);
  }
  return dir;
}

test('detects an AWS key and masks it', async () => {
  const dir = await tmpRepo({ 'config.js': `const key = "${'AKIA' + 'IOSFODNN7DEMOKEY'}";` });
  const { findings } = await scanDirectory(dir);
  const f = findings.find((x) => x.ruleId === 'aws-access-key');
  assert.ok(f);
  assert.equal(f.line, 1);
  assert.ok(!f.masked.includes('DEMOK'), 'secret must be masked');
});

test('flags committed .env but not .env.example', async () => {
  const dir = await tmpRepo({ '.env': 'X=1', '.env.example': 'X=' });
  const { findings } = await scanDirectory(dir);
  const files = findings.filter((x) => x.ruleId === 'sensitive-file').map((x) => x.file);
  assert.deepEqual(files, ['.env']);
});

test('downgrades placeholders to low severity', async () => {
  const dir = await tmpRepo({ 'a.py': 'password = "your_password_here"' });
  const { findings } = await scanDirectory(dir);
  assert.equal(findings[0].severity, 'low');
  assert.equal(findings[0].placeholder, true);
});

test('ignores env lookups', async () => {
  const dir = await tmpRepo({ 'a.js': 'const token = process.env.API_TOKEN;' });
  const { findings } = await scanDirectory(dir);
  assert.equal(findings.length, 0);
});

test('skips node_modules', async () => {
  const dir = await tmpRepo({ 'node_modules/x/index.js': `const k = "${'sk_live_' + 'abcdefghijklmnopqrstuvwxyz1234'}";` });
  const { findings } = await scanDirectory(dir);
  assert.equal(findings.length, 0);
});

test('score drops with severity', () => {
  assert.equal(summarize([]).score, 100);
  assert.equal(summarize([{ severity: 'low', placeholder: true }]).score, 100);
  assert.equal(summarize([{ severity: 'critical' }]).score, 75);
});

test('entropy and helpers', () => {
  assert.ok(shannonEntropy('aaaaaaaa') < 1);
  assert.ok(shannonEntropy('xK9#mQ2$vL7@pR4!') > 3.5);
  assert.equal(mask('abcdefghijkl'), 'abcd*****jkl');
  assert.ok(looksLikePlaceholder('changeme', ''));
});

test('parses GitHub URLs', () => {
  assert.equal(parseGithubUrl('https://github.com/expressjs/express').repo, 'express');
  assert.equal(parseGithubUrl('github.com/expressjs/express.git').owner, 'expressjs');
  assert.equal(parseGithubUrl('https://github.com/a/b/tree/dev/src').branch, 'dev');
  assert.equal(parseGithubUrl('not a url'), null);
});
