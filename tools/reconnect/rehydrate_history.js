// rehydrate_history.js -- re-read the decrypted history chunks this tool kept, with the CURRENT
// mapper, and fill in fields the run that downloaded them did not capture. No network.
//
// WHY THIS EXISTS. A history chunk is the primary artifact: the phone uploaded it, the extractor
// downloaded it once, and its CDN url expires within weeks. Everything in history_recovered.json is
// a MAPPING of that artifact. When the mapper turned out to be missing a field -- the group sender,
// `key.participant`, for 29,864 messages banked by earlier runs -- those messages could only be
// repaired by asking the phone for that history again, which depends on a window WhatsApp
// rate-limits and may decline. Chunks are kept now, so the same mistake costs one offline pass
// instead.
//
//   node rehydrate_history.js                 re-read ./history_chunks into ./history_all.json
//   node rehydrate_history.js --dir <path>    chunks from somewhere else
//   node rehydrate_history.js --dry-run       report what would change, write nothing
//
// It only FILLS: a field the banked record already has is never overwritten, because the banked copy
// is the one the anchors and the resume ledger were built from. Messages present in a chunk but not
// in the ledger are added.

const fs = require('fs'), path = require('path'), zlib = require('zlib');

const argv = process.argv.slice(2);
const arg = (f, d) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
const DRY = argv.includes('--dry-run');
const DIR = path.resolve(arg('--dir', 'history_chunks'));
const LEDGER = path.resolve(arg('--ledger', 'history_all.json'));

// The message's CONTENT type. Object.keys(message)[0] was used, and when the protobuf carries
// messageContextInfo (metadata) ahead of the content, that is what got recorded as the type --
// 287 recovered messages were typed "messageContextInfo". Skip the metadata keys.
const META_KEYS=new Set(['messageContextInfo','senderKeyDistributionMessage']);
function mtype(m){ if(!m) return '?'; for(const k of Object.keys(m)){ if(!META_KEYS.has(k) && m[k]!=null) return k; } return '?'; }
function need(name) {
  for (const c of [path.resolve(process.cwd(), name), path.join(__dirname, name)])
    if (fs.existsSync(c)) return c;
  console.error(`[x] ${name} not found (looked in ${process.cwd()} and ${__dirname})`);
  process.exit(4);
}

let B;
try { B = require('@whiskeysockets/baileys'); }
catch (e) { console.error('[x] Baileys not installed here — run `npm install` in this folder first.'); process.exit(4); }

// The SAME mapping the extractor uses. Kept identical on purpose: this tool exists to apply the
// current mapper to old chunks, so any divergence between the two would defeat it.
const txt = m => { if (!m) return ''; const c = m.conversation || m.extendedTextMessage?.text
  || m.imageMessage?.caption || m.videoMessage?.caption || m.documentMessage?.caption; return c || ''; };
function flatten(hs) {
  const out = [];
  for (const conv of (hs.conversations || [])) {
    for (const hm of (conv.messages || [])) {
      const w = hm.message; if (!w || !w.key) continue;
      out.push({ chat: conv.id || w.key.remoteJid, id: w.key.id, fromMe: !!w.key.fromMe,
                 participant: (w.key && w.key.participant) || w.participant || null,
                 pushName: w.pushName || null,
                 ts: Number(w.messageTimestamp) || 0, text: txt(w.message),
                 type: mtype(w.message) });
    }
  }
  return out;
}

if (!fs.existsSync(DIR)) {
  console.error(`[x] no chunk directory at ${DIR}\n`
    + `    Chunks are kept by runs of history_extract.js from 2026-10-04 onward. A ledger banked\n`
    + `    before that has none, and its missing fields can only come from asking the phone again\n`
    + `    (wawf --history --history-refetch).`);
  process.exit(4);
}
const files = fs.readdirSync(DIR).filter(f => f.endsWith('.pb.gz')).sort();
if (!files.length) { console.error(`[x] ${DIR} holds no .pb.gz chunks`); process.exit(4); }

const ledgerPath = fs.existsSync(LEDGER) ? LEDGER : need('history_all.json');
const L = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'));
const master = new Map();
for (const m of (L.messages || [])) if (m.id) master.set(m.id, m);
console.error(`[*] ${files.length} chunk(s) in ${DIR}`);
console.error(`[*] ledger ${ledgerPath}: ${master.size} message(s)`);

const EMPTY = v => v === null || v === undefined || v === '';
let added = 0, enriched = 0, seen = 0, bad = 0;
const gained = {};
for (const f of files) {
  let msgs;
  try {
    const inf = zlib.gunzipSync(fs.readFileSync(path.join(DIR, f)));
    msgs = flatten(B.proto.HistorySync.decode(inf));
  } catch (e) { bad++; console.error(`  [!] ${f}: ${e.message}`); continue; }
  for (const m of msgs) {
    if (!m.id) continue;
    seen++;
    const cur = master.get(m.id);
    if (!cur) { master.set(m.id, m); added++; continue; }
    let filled = false;
    for (const k of Object.keys(m)) {
      if (EMPTY(m[k])) continue;
      if (EMPTY(cur[k])) { cur[k] = m[k]; filled = true; gained[k] = (gained[k] || 0) + 1; }
    }
    if (filled) enriched++;
  }
}
console.error(`[*] ${seen} message(s) across the chunks: ${added} not in the ledger, ${enriched} enriched`
  + (bad ? `, ${bad} chunk(s) unreadable` : ''));
for (const [k, n] of Object.entries(gained).sort((a, b) => b[1] - a[1]))
  console.error(`      ${k}: filled on ${n} message(s)`);

if (DRY) { console.error('[*] --dry-run: nothing written'); process.exit(0); }
if (!added && !enriched) { console.error('[*] nothing to change'); process.exit(0); }

const arr = [...master.values()];
const byChat = {};
for (const m of arr) byChat[m.chat] = (byChat[m.chat] || 0) + 1;
const out = { recovered_total: arr.length, new_not_on_disk: arr.length, by_chat: byChat, messages: arr };
fs.writeFileSync(ledgerPath + '.tmp', JSON.stringify(out, null, 1));
fs.renameSync(ledgerPath + '.tmp', ledgerPath);
// the human-facing copy the exporters read, kept in step
const RECOVERED = path.join(path.dirname(ledgerPath), 'history_recovered.json');
fs.writeFileSync(RECOVERED + '.tmp', JSON.stringify(out, null, 1));
fs.renameSync(RECOVERED + '.tmp', RECOVERED);
console.error(`[+] ${ledgerPath} and ${RECOVERED} updated — re-run the export to pick it up:`);
console.error(`    wawf <PROFILE> --history --out <dir>     (or any --out; the merge reads the ledger)`);
