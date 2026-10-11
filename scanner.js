// Reads a folder the user picked in Chrome and returns a snapshot of it.
// Browsers cannot "watch" a folder, so the app takes a snapshot every few seconds
// and compares it with the previous one (see detector.js: diffSnapshots).

import { shannonEntropy, entropyEligible } from './detector.js';

const SAMPLE_BYTES = 16384;
const MAX_FILES = 5000;
const MAX_DEPTH = 8;
const MAX_BASELINE_READS = 1500;
const MAX_READS_PER_SCAN = 300;
const SKIP_DIRS = new Set(['node_modules', '.git']);

export const supported = typeof window !== 'undefined' && 'showDirectoryPicker' in window;

export async function pickFolder() {
  return window.showDirectoryPicker({ id: 'ransomware-watch', mode: 'read' });
}

async function listFiles(dir, prefix, depth, out) {
  for await (const [name, handle] of dir.entries()) {
    if (out.length >= MAX_FILES) return;
    const path = prefix ? `${prefix}/${name}` : name;
    if (handle.kind === 'file') out.push({ path, handle });
    else if (depth < MAX_DEPTH && !SKIP_DIRS.has(name)) await listFiles(handle, path, depth + 1, out);
  }
}

/**
 * @param dirHandle  the folder the user chose
 * @param prev       previous snapshot (Map) or null on the first scan
 * @returns { snapshot: Map<path,{size,mtime,ent}>, truncated: boolean }
 */
export async function scan(dirHandle, prev) {
  const files = [];
  await listFiles(dirHandle, '', 0, files);
  const snapshot = new Map();
  let reads = 0;
  const readLimit = prev ? MAX_READS_PER_SCAN : MAX_BASELINE_READS;

  for (const { path, handle } of files) {
    let file;
    try {
      file = await handle.getFile();
    } catch {
      continue; // file vanished or is locked between listing and reading
    }
    const old = prev && prev.get(path);
    let ent = old ? old.ent : null;
    const changed = !old || old.size !== file.size || old.mtime !== file.lastModified;

    if (changed && file.size > 0 && entropyEligible(path) && reads < readLimit) {
      try {
        const buf = await file.slice(0, SAMPLE_BYTES).arrayBuffer();
        ent = shannonEntropy(new Uint8Array(buf));
        reads++;
      } catch {
        // unreadable right now; keep previous entropy value
      }
    }
    snapshot.set(path, { size: file.size, mtime: file.lastModified, ent });
  }
  return { snapshot, truncated: files.length >= MAX_FILES };
}

/** Timer that keeps ticking when the tab is in the background (workers are not throttled like page timers). */
export function makeTicker(ms, onTick) {
  const code = `let id; onmessage = e => { clearInterval(id); if (e.data === 'start') id = setInterval(() => postMessage(1), ${Number(ms)}); };`;
  const url = URL.createObjectURL(new Blob([code], { type: 'text/javascript' }));
  const worker = new Worker(url);
  worker.onmessage = onTick;
  worker.postMessage('start');
  return () => {
    worker.postMessage('stop');
    worker.terminate();
    URL.revokeObjectURL(url);
  };
}

// ---- Self-test: writes NEW harmless files in a sub-folder, then removes them ----

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function writeFile(dir, name, data) {
  const fh = await dir.getFileHandle(name, { create: true });
  const w = await fh.createWritable();
  await w.write(data);
  await w.close();
}

function randomBytes(n) {
  const out = new Uint8Array(n);
  for (let o = 0; o < n; o += 65536) crypto.getRandomValues(out.subarray(o, Math.min(n, o + 65536)));
  return out;
}

/**
 * Imitates what ransomware does, but only to files it creates itself inside
 * "_detector_selftest". Your own files are never opened for writing.
 */
export async function runSelfTest(rootHandle, waitMs, onStep) {
  const perm = await rootHandle.requestPermission({ mode: 'readwrite' });
  if (perm !== 'granted') throw new Error('Write permission was not granted, so the self-test cannot run.');

  const dir = await rootHandle.getDirectoryHandle('_detector_selftest', { create: true });
  const sentence = 'Quarterly notes: nothing unusual to report this week. ';
  const text = new TextEncoder().encode(sentence.repeat(500));
  const names = Array.from({ length: 8 }, (_, i) => `sample_${i + 1}.txt`);

  try {
    onStep('Step 1 of 3: creating 8 plain-text sample files');
    for (const n of names) await writeFile(dir, n, text);
    await sleep(waitMs);

    onStep('Step 2 of 3: overwriting them with random data (what encryption looks like)');
    for (const n of names) await writeFile(dir, n, randomBytes(20000));
    await sleep(waitMs);

    onStep('Step 3 of 3: adding .locked files and a fake ransom note');
    for (const n of names.slice(0, 4)) await writeFile(dir, `${n}.locked`, randomBytes(2048));
    await writeFile(dir, 'HOW_TO_DECRYPT_FILES.txt', 'Self-test note. Nothing was encrypted.');
    await sleep(waitMs + 2000);
  } finally {
    onStep('Cleaning up test files');
    try {
      await rootHandle.removeEntry('_detector_selftest', { recursive: true });
    } catch {
      // if removal fails the person can delete the folder by hand
    }
  }
}
