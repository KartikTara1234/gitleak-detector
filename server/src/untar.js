// Minimal pure-Node .tar.gz extractor (ustar + GNU longname + pax path headers).
// Exists so the scanner works on hosts without a `tar` binary (Vercel/Lambda).
import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';

const BLOCK = 512;

function str(buf, start, len) {
  const slice = buf.subarray(start, start + len);
  const nul = slice.indexOf(0);
  return slice.subarray(0, nul === -1 ? len : nul).toString('utf8');
}
function octal(buf, start, len) {
  const s = str(buf, start, len).trim();
  return s ? parseInt(s, 8) : 0;
}

/**
 * Extract a gzipped tar buffer/file into destDir.
 * @param {string|Buffer} src   path to .tar.gz or its bytes
 * @param {string} destDir
 * @param {{strip?: number, maxBytes?: number}} opts  strip = leading path components to drop
 * @returns {Promise<{files: number, topDir: string|null}>}
 */
export async function extractTarGz(src, destDir, { strip = 0, maxBytes = 200 * 1024 * 1024 } = {}) {
  const gz = Buffer.isBuffer(src) ? src : await fs.readFile(src);
  const tar = zlib.gunzipSync(gz, { maxOutputLength: maxBytes });
  const root = path.resolve(destDir);
  await fs.mkdir(root, { recursive: true });

  let off = 0;
  let files = 0;
  let topDir = null;
  let pendingName = null; // from GNU 'L' or pax 'path'

  while (off + BLOCK <= tar.length) {
    const hdr = tar.subarray(off, off + BLOCK);
    if (hdr.every((b) => b === 0)) break; // end-of-archive
    let name = str(hdr, 0, 100);
    const size = octal(hdr, 124, 12);
    const type = String.fromCharCode(hdr[156] || 48);
    const prefix = str(hdr, 345, 155);
    if (prefix && !pendingName) name = `${prefix}/${name}`;
    if (pendingName) { name = pendingName; pendingName = null; }
    const dataStart = off + BLOCK;
    const dataEnd = dataStart + size;
    off = dataStart + Math.ceil(size / BLOCK) * BLOCK;

    if (type === 'L') { pendingName = str(tar, dataStart, size); continue; }           // GNU long name
    if (type === 'x' || type === 'g') {                                                 // pax headers
      const rec = tar.subarray(dataStart, dataEnd).toString('utf8');
      const m = rec.match(/\d+ path=([^\n]*)\n/);
      if (type === 'x' && m) pendingName = m[1];
      continue;
    }

    const parts = name.split('/').filter((p) => p && p !== '.');
    if (parts.length && topDir === null) topDir = parts[0];
    if (parts.some((p) => p === '..')) continue;        // path traversal
    const rel = parts.slice(strip).join('/');
    if (!rel) continue;
    const full = path.resolve(root, rel);
    if (!full.startsWith(root + path.sep) && full !== root) continue;

    if (type === '5') { await fs.mkdir(full, { recursive: true }); continue; }           // directory
    if (type === '0' || type === '\0' || type === '7') {                                 // regular file
      await fs.mkdir(path.dirname(full), { recursive: true });
      await fs.writeFile(full, tar.subarray(dataStart, dataEnd));
      files++;
    }
    // symlinks (2), hardlinks (1), devices etc. are skipped on purpose
  }
  return { files, topDir };
}
