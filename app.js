import { Analyzer, diffSnapshots } from './detector.js';
import { supported, pickFolder, scan, makeTicker, runSelfTest } from './scanner.js';

const $ = (id) => document.getElementById(id);
const analyzer = new Analyzer();

const state = {
  mode: 'idle',          // idle | watching | demo
  root: null,
  prev: null,
  files: 0,
  lastScan: null,
  scanning: false,
  stopTicker: null,
  demoTimer: null,
  feed: [],
  prevLevel: 'calm',
  selfTesting: false,
};

const SIGNAL_LABEL = {
  ext: 'Ransomware extension',
  appended: 'Extension appended',
  note: 'Ransom-note name',
  entropy: 'Contents became random',
};
const KIND_LABEL = { created: 'Created', modified: 'Modified', deleted: 'Deleted', renamed: 'Renamed' };

// ---------- helpers ----------

const pad = (n) => String(n).padStart(2, '0');
const clock = (t) => { const d = new Date(t); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };

function showNotice(text) {
  $('notice').textContent = text || '';
  $('notice').hidden = !text;
}
function showProgress(text) {
  $('progress').textContent = text || '';
  $('progress').hidden = !text;
}
function readSettings() {
  const num = (id, fallback, min, max) => {
    const v = Number($(id).value);
    return Number.isFinite(v) ? Math.min(max, Math.max(min, v)) : fallback;
  };
  return {
    threshold: num('optThreshold', 10, 3, 200),
    windowSec: num('optWindow', 5, 1, 60),
    intervalSec: num('optInterval', 3, 1, 30),
  };
}

// ---------- rendering ----------

function renderFeed() {
  const rows = $('rows');
  rows.replaceChildren();
  if (!state.feed.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4; td.className = 'empty';
    td.textContent = 'Nothing yet. Changes will appear here as they happen.';
    tr.append(td); rows.append(tr);
    return;
  }
  for (const ev of state.feed.slice(0, 200)) {
    const tr = document.createElement('tr');
    if (ev.signals.length) tr.className = 'flag';
    const time = document.createElement('td'); time.dataset.label = 'Time'; time.textContent = clock(ev.t);
    const kind = document.createElement('td'); kind.dataset.label = 'Change'; kind.textContent = KIND_LABEL[ev.kind] || ev.kind;
    const file = document.createElement('td');
    file.dataset.label = 'File';
    file.textContent = ev.kind === 'renamed' ? `${ev.from}  →  ${ev.path}` : ev.path;   // textContent: file names are untrusted
    const sig = document.createElement('td');
    sig.dataset.label = 'Warning signs';
    for (const s of ev.signals) {
      const tag = document.createElement('span');
      tag.className = 'tag'; tag.textContent = SIGNAL_LABEL[s] || s;
      sig.append(tag);
    }
    tr.append(time, kind, file, sig);
    rows.append(tr);
  }
}

function headlineFor(mode, a) {
  const demo = mode === 'demo' ? 'Demo: ' : '';
  if (mode === 'idle') return {
    h: 'Choose a folder to watch.',
    s: 'The page checks that folder every few seconds and warns you if files start changing the way they do during a ransomware attack.',
  };
  if (a.level === 'alert') return {
    h: `${demo}This looks like ransomware.`,
    s: `${a.reasons.join('. ')}. ${mode === 'demo' ? 'No real files were touched.' : 'Disconnect this computer from the network and avoid opening the affected files.'}`,
  };
  if (a.level === 'watch') return {
    h: `${demo}Unusual activity.`,
    s: `${a.reasons.join('. ') || 'More changes than usual'}. This can be a backup, install or build, so check what is running.`,
  };
  return {
    h: mode === 'demo' ? 'Demo: all quiet so far.' : (state.lastScan ? `Quiet. ${state.files.toLocaleString()} files watched.` : 'Reading the folder…'),
    s: mode === 'demo' ? 'Watch the score as simulated activity ramps up. No real files are involved.' : 'Nothing unusual in the last minute.',
  };
}

function render() {
  const now = Date.now();
  const a = analyzer.assess(now);
  const level = state.mode === 'idle' ? 'idle' : a.level;

  document.body.dataset.level = level;
  $('score').textContent = state.mode === 'idle' ? '0' : a.score;
  $('arc').style.strokeDashoffset = String(282.74 * (1 - (state.mode === 'idle' ? 0 : a.score) / 100));

  const { h, s } = headlineFor(state.mode, a);
  $('headline').textContent = h;
  $('subline').textContent = s;

  $('pill').textContent = {
    idle: 'Not watching',
    calm: state.mode === 'demo' ? 'Demo running' : 'Watching',
    watch: 'Unusual activity',
    alert: 'Alert',
  }[level];

  $('pickBtn').hidden = state.mode !== 'idle';
  $('demoBtn').hidden = state.mode !== 'idle';
  $('stopBtn').hidden = state.mode === 'idle';
  $('stopBtn').textContent = state.mode === 'demo' ? 'End demo' : 'Stop watching';
  $('selfTestBtn').hidden = state.mode !== 'watching';
  $('selfTestBtn').disabled = state.selfTesting;

  $('statFiles').textContent = state.mode === 'watching' ? state.files.toLocaleString() : '0';
  $('statBurst').textContent = a.burstCount;
  $('statWin').textContent = analyzer.opts.windowSec;
  $('statLast').textContent = state.lastScan ? clock(state.lastScan) : '–';
  $('statFolder').textContent = state.mode === 'watching' && state.root ? state.root.name : (state.mode === 'demo' ? 'Simulated (no folder)' : 'None chosen');

  // Latch the banner when we enter the alert level.
  if (state.mode !== 'idle' && a.level === 'alert' && state.prevLevel !== 'alert') raiseAlert(a);
  state.prevLevel = state.mode === 'idle' ? 'calm' : a.level;
  document.title = level === 'alert' ? '⚠ Alert – Ransomware Watch' : 'Ransomware Watch';
}

function raiseAlert(a) {
  $('latchTitle').textContent = `Possible ransomware activity at ${clock(Date.now())}`;
  $('latchBody').textContent = `${a.reasons.join('. ')}.`;
  $('latch').hidden = false;
  if ('Notification' in window && Notification.permission === 'granted') {
    try { new Notification('Possible ransomware activity', { body: a.reasons.join('. ') }); } catch { /* some browsers block constructor use */ }
  }
}

function addFeed(events) {
  state.feed.unshift(...events.slice().reverse());
  if (state.feed.length > 300) state.feed.length = 300;
  renderFeed();
}

// ---------- watching a real folder ----------

async function tick() {
  if (state.scanning || !state.root || state.mode !== 'watching') return;
  state.scanning = true;
  try {
    const { snapshot, truncated } = await scan(state.root, state.prev);
    if (state.mode !== 'watching') return;   // stopped while scanning
    if (state.prev) {
      const changes = diffSnapshots(state.prev, snapshot);
      if (changes.length) addFeed(analyzer.ingest(changes));
    } else {
      showProgress('');
    }
    state.prev = snapshot;
    state.files = snapshot.size;
    state.lastScan = Date.now();
    showNotice(truncated ? 'This folder is large, so only the first 5,000 files are being watched. Choose a smaller folder for full coverage.' : '');
  } catch (err) {
    stopAll();
    showNotice(`Lost access to the folder (${err.name}). Choose it again to resume.`);
  } finally {
    state.scanning = false;
    render();
  }
}

async function startWatching() {
  showNotice('');
  let handle;
  try {
    handle = await pickFolder();
  } catch (err) {
    if (err.name !== 'AbortError') showNotice(`The browser could not open that folder (${err.message}). Pick a sub-folder instead of a drive root or system folder.`);
    return;
  }
  const cfg = readSettings();
  analyzer.reset();
  analyzer.configure({ threshold: cfg.threshold, windowSec: cfg.windowSec });
  state.root = handle;
  state.prev = null;
  state.files = 0;
  state.lastScan = null;
  state.feed = [];
  state.mode = 'watching';
  renderFeed();
  showProgress('Reading the folder to learn what normal looks like…');
  state.stopTicker = makeTicker(cfg.intervalSec * 1000, tick);
  tick();
  render();
}

function stopAll() {
  if (state.stopTicker) state.stopTicker();
  state.stopTicker = null;
  if (state.demoTimer) clearInterval(state.demoTimer);
  state.demoTimer = null;
  state.mode = 'idle';
  state.root = null;
  state.prev = null;
  showProgress('');
  render();
}

// ---------- demo (nothing touches disk) ----------

function startDemo() {
  showNotice('');
  const cfg = readSettings();
  analyzer.reset();
  analyzer.configure({ threshold: cfg.threshold, windowSec: cfg.windowSec });
  state.mode = 'demo';
  state.feed = [];
  state.lastScan = Date.now();
  renderFeed();

  const docs = ['Budget 2026.xlsx', 'Photos/holiday.txt', 'Taxes/return.txt', 'Contracts/lease.txt', 'Notes/ideas.txt', 'Work/report.txt', 'Work/plan.txt', 'Family/recipes.txt', 'School/essay.txt', 'Invoices/may.txt', 'Invoices/june.txt', 'Letters/draft.txt'];
  let step = 0;
  state.demoTimer = setInterval(() => {
    const changes = [];
    if (step < 3) {
      changes.push({ kind: 'modified', path: docs[step], ent: 4.4, prevEnt: 4.3 });
    } else if (step < 6) {
      for (let i = 0; i < 4; i++) changes.push({ kind: 'modified', path: docs[(step * 3 + i) % docs.length], ent: 4.5, prevEnt: 4.4 });
    } else if (step < 12) {
      for (let i = 0; i < 3; i++) {
        const from = docs[(step * 2 + i) % docs.length];
        changes.push({ kind: 'renamed', path: `${from}.locked`, from, appended: true, ent: 7.96, prevEnt: 4.4 });
      }
    } else if (step === 12) {
      changes.push({ kind: 'created', path: 'HOW_TO_DECRYPT_FILES.txt', ent: 4.2, prevEnt: null });
    } else if (step > 24) {
      stopAll();
      return;
    }
    if (changes.length) addFeed(analyzer.ingest(changes));
    state.lastScan = Date.now();
    step++;
    render();
  }, 700);
  render();
}

// ---------- self-test in the chosen folder ----------

async function selfTest() {
  if (state.selfTesting || !state.root) return;
  state.selfTesting = true;
  render();
  try {
    const wait = readSettings().intervalSec * 1000 + 1000;
    await runSelfTest(state.root, wait, showProgress);
    showProgress('Self-test finished and the test files were removed.');
    setTimeout(() => showProgress(''), 6000);
  } catch (err) {
    showProgress('');
    showNotice(err.message || 'The self-test could not run.');
  } finally {
    state.selfTesting = false;
    render();
  }
}

// ---------- wiring ----------

$('pickBtn').addEventListener('click', startWatching);
$('stopBtn').addEventListener('click', stopAll);
$('demoBtn').addEventListener('click', startDemo);
$('selfTestBtn').addEventListener('click', selfTest);
$('dismissBtn').addEventListener('click', () => { $('latch').hidden = true; });
$('clearBtn').addEventListener('click', () => { state.feed = []; renderFeed(); });
for (const id of ['optThreshold', 'optWindow']) {
  $(id).addEventListener('change', () => {
    const c = readSettings();
    analyzer.configure({ threshold: c.threshold, windowSec: c.windowSec });
    render();
  });
}
$('notifyBtn').addEventListener('click', async () => {
  await Notification.requestPermission();
  $('notifyBtn').hidden = Notification.permission !== 'default';
});

if ('Notification' in window && Notification.permission === 'default') $('notifyBtn').hidden = false;

if (!supported) {
  $('pickBtn').disabled = true;
  showNotice('Live folder monitoring is not supported in this browser. On phones, you can try the demo; to monitor a folder, use Chrome or Edge on a desktop computer.');
} else if (!window.isSecureContext) {
  $('pickBtn').disabled = true;
  showNotice('Folder access needs a secure page (https:// or localhost).');
}

setInterval(() => { if (state.mode !== 'idle') render(); }, 1000);   // lets the score fade as time passes
renderFeed();
render();
