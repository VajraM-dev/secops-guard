'use strict';
// File cache under <STATE_DIR>/cache. Any fs problem degrades to calling fn directly.
//
// Entries are authenticated with an HMAC over the key, the expiry and the value, using a
// per-machine secret in <STATE_DIR>/cache.key (0600). Without it, anything able to write a
// file into the cache directory could flip a stored "deny" verdict into an "allow" and have
// it believed for the life of the entry - the filename is just sha256(key), so it is
// computable. An entry that fails verification is treated as a miss, not as data.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { stateDir } = require('./config');

let KEY = null;
function hmacKey(dir) {
  if (KEY) return KEY;
  const kf = path.join(dir, 'cache.key');
  try {
    KEY = fs.readFileSync(kf);
  } catch {
    KEY = crypto.randomBytes(32);
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(kf, KEY, { mode: 0o600 });
    } catch { /* keep the in-memory key; the cache just will not persist across runs */ }
  }
  return KEY;
}

const tag = (key, dir, expires, value) =>
  crypto.createHmac('sha256', hmacKey(dir)).update(`${key}\u0000${expires}\u0000${JSON.stringify(value)}`).digest('hex');

async function cached(key, ttlMs, fn, now = Date.now()) {
  let file;
  let dir;
  try {
    dir = stateDir();
    file = path.join(dir, 'cache', `${crypto.createHash('sha256').update(String(key)).digest('hex')}.json`);
    const hit = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (hit && typeof hit.expires === 'number' && hit.expires > now && 'value' in hit) {
      const want = tag(String(key), dir, hit.expires, hit.value);
      // timingSafeEqual needs equal lengths; a wrong-length tag is already a failure.
      const got = String(hit.mac || '');
      if (got.length === want.length && crypto.timingSafeEqual(Buffer.from(got), Buffer.from(want))) return hit.value;
    }
  } catch { /* miss */ }
  const value = await fn();
  if (file && value !== undefined) {
    try {
      const expires = now + ttlMs;
      fs.mkdirSync(path.dirname(file), { recursive: true });
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify({ expires, value, mac: tag(String(key), dir, expires, value) }));
      fs.renameSync(tmp, file);
    } catch { /* best effort */ }
  }
  return value;
}

module.exports = { cached };
