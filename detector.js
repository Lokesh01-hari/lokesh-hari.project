// Detection engine. Pure logic, no browser APIs, so it can be unit-tested in Node.
//
// Signals (each is a heuristic, none is proof of ransomware):
//   burst     many file changes in a short window
//   entropy   a file's contents jumped from low to high randomness (encryption looks like noise)
//   ext       a file was created/renamed with a known ransomware extension
//   appended  "report.docx" was replaced by "report.docx.<something>"
//   note      a file named like a ransom note appeared
//   delete    many files deleted

export const DEFAULTS = Object.freeze({
  threshold: 10,        // changes inside windowSec that count as a full burst
  windowSec: 5,
  signalWindowSec: 60,  // strong signals stay in the score this long
});

export const LEVELS = Object.freeze({ watch: 25, alert: 60 });

const SUSPICIOUS_EXT = new Set([
  'locked', 'encrypted', 'encrypt', 'crypt', 'crypted', 'crypto', 'enc',
  'cerber', 'locky', 'wncry', 'wnry', 'wcry', 'ryk', 'ryuk', 'conti', 'lockbit',
  'akira', 'blackcat', 'petya', 'zepto', 'crab', 'dharma', 'phobos', 'djvu',
  'medusa', 'babuk', 'clop', 'cl0p', 'mallox', 'rhysida', 'crinf', 'kraken',
]);

// Formats that are naturally high-entropy: their entropy says nothing about encryption.
const COMPRESSED = new Set([
  'zip', '7z', 'rar', 'gz', 'bz2', 'xz', 'zst', 'tgz', 'jar', 'apk',
  'docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp', 'epub',
  'jpg', 'jpeg', 'png', 'gif', 'webp', 'heic', 'avif',
  'mp3', 'aac', 'flac', 'ogg', 'm4a', 'mp4', 'mkv', 'mov', 'avi', 'webm',
  'pdf', 'woff', 'woff2',
]);

const NOTE_PATTERN =
  /(how[_\- .]?to[_\- .]?(decrypt|recover|restore|get)|(decrypt|recover|restore)[_\- .]?(my[_\- .]?)?(your[_\- .]?)?(files|data|instructions)|ransom|your[_\- .]?files[_\- .]?(are|have)|readme[_\- .]?(to[_\- .]?)?(decrypt|restore|recover)|_readme_|!{3,})/i;
const NOTE_EXT = new Set(['txt', 'html', 'htm', 'hta', 'rtf', 'url']);

export function extOf(path) {
  const name = path.split('/').pop();
  const i = name.lastIndexOf('.');
  return i > 0 ? name.slice(i + 1).toLowerCase() : '';
}

export function baseName(path) {
  return path.split('/').pop();
}

export function shannonEntropy(bytes) {
  if (!bytes || !bytes.length) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let h = 0;
  const n = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (counts[i]) {
      const p = counts[i] / n;
      h -= p * Math.log2(p);
    }
  }
  return h;
}

export function entropyEligible(path) {
  return !COMPRESSED.has(extOf(path));
}

export function isSuspiciousExt(path) {
  return SUSPICIOUS_EXT.has(extOf(path));
}

export function looksLikeRansomNote(path) {
  return NOTE_EXT.has(extOf(path)) && NOTE_PATTERN.test(baseName(path));
}

/**
 * Compare two snapshots (Map<path, {size, mtime, ent}>) and list what changed.
 * A delete+create pair with identical size and mtime is reported as a rename.
 * A delete of "x.doc" plus a create of "x.doc.abc" is reported as an appended-extension rename.
 */
export function diffSnapshots(prev, curr) {
  const changes = [];
  const created = [];
  const deletedByKey = new Map();   // "size|mtime" -> [paths]
  const deletedSet = new Set();

  for (const [path, c] of curr) {
    const o = prev.get(path);
    if (!o) created.push(path);
    else if (o.size !== c.size || o.mtime !== c.mtime) {
      changes.push({ kind: 'modified', path, size: c.size, ent: c.ent, prevEnt: o.ent });
    }
  }
  for (const [path, o] of prev) {
    if (curr.has(path)) continue;
    deletedSet.add(path);
    const key = `${o.size}|${o.mtime}`;
    if (!deletedByKey.has(key)) deletedByKey.set(key, []);
    deletedByKey.get(key).push(path);
  }

  const leftover = [];
  for (const path of created) {
    const c = curr.get(path);
    const bucket = deletedByKey.get(`${c.size}|${c.mtime}`);
    if (bucket && bucket.length) {
      const from = bucket.pop();
      deletedSet.delete(from);
      changes.push({
        kind: 'renamed', path, from, size: c.size, ent: c.ent, prevEnt: prev.get(from).ent,
        appended: path.startsWith(from + '.'),
      });
    } else leftover.push(path);
  }

  for (const path of leftover) {
    const c = curr.get(path);
    const stem = path.includes('.') ? path.slice(0, path.lastIndexOf('.')) : null;
    if (stem && deletedSet.has(stem)) {
      deletedSet.delete(stem);
      changes.push({
        kind: 'renamed', path, from: stem, size: c.size, ent: c.ent,
        prevEnt: prev.get(stem).ent, appended: true,
      });
    } else {
      changes.push({ kind: 'created', path, size: c.size, ent: c.ent, prevEnt: null });
    }
  }

  for (const path of deletedSet) changes.push({ kind: 'deleted', path, size: 0, ent: null, prevEnt: null });
  return changes;
}

/** Which warning signs does a single change show? */
export function classify(change) {
  const signals = [];
  const { kind, path } = change;
  if ((kind === 'created' || kind === 'renamed') && isSuspiciousExt(path)) signals.push('ext');
  if (kind === 'renamed' && change.appended) signals.push('appended');
  if (kind === 'created' && looksLikeRansomNote(path)) signals.push('note');
  if (
    (kind === 'modified' || kind === 'renamed') &&
    entropyEligible(path) &&
    change.ent != null && change.prevEnt != null &&
    change.ent >= 7.2 && change.prevEnt <= 6.5
  ) signals.push('entropy');
  return signals;
}

export class Analyzer {
  constructor(opts = {}) {
    this.opts = { ...DEFAULTS, ...opts };
    this.events = [];
  }

  configure(opts) {
    Object.assign(this.opts, opts);
  }

  reset() {
    this.events = [];
  }

  ingest(changes, now = Date.now()) {
    const out = [];
    for (const ch of changes) {
      const ev = { t: now, ...ch, signals: classify(ch) };
      this.events.push(ev);
      out.push(ev);
    }
    this._prune(now);
    return out;
  }

  _prune(now) {
    const keepMs = Math.max(this.opts.signalWindowSec, this.opts.windowSec) * 1000;
    while (this.events.length && now - this.events[0].t > keepMs) this.events.shift();
    if (this.events.length > 5000) this.events.splice(0, this.events.length - 5000);
  }

  assess(now = Date.now()) {
    this._prune(now);
    const { threshold, windowSec, signalWindowSec } = this.opts;
    const burstEvents = this.events.filter(e => now - e.t <= windowSec * 1000);
    const sigEvents = this.events.filter(e => now - e.t <= signalWindowSec * 1000);
    const count = (name) => sigEvents.filter(e => e.signals.includes(name)).length;

    const parts = [];
    const add = (points, text) => { if (points > 0) parts.push({ points, text }); };
    const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

    const burstPts = Math.min(40, Math.round((40 * burstEvents.length) / threshold));
    if (burstEvents.length >= Math.ceil(threshold / 2)) {
      add(burstPts, `${plural(burstEvents.length, 'change')} in the last ${windowSec} s`);
    }

    const ent = count('entropy');
    add(Math.min(50, ent * 25), `${plural(ent, 'file')} turned into random-looking data`);

    const ext = count('ext');
    add(Math.min(60, ext * 30), `${plural(ext, 'file')} with a ransomware-style extension`);

    const app = count('appended');
    add(Math.min(40, app * 20), `${plural(app, 'file')} renamed by appending an extension`);

    const note = count('note');
    add(Math.min(40, note * 40), `A file named like a ransom note appeared`);

    const del = sigEvents.filter(e => e.kind === 'deleted').length;
    add(Math.min(20, del * 4), `${plural(del, 'file')} deleted`);

    const score = Math.min(100, parts.reduce((s, p) => s + p.points, 0));
    const level = score >= LEVELS.alert ? 'alert' : score >= LEVELS.watch ? 'watch' : 'calm';
    return { score, level, burstCount: burstEvents.length, reasons: parts.map(p => p.text) };
  }
}
