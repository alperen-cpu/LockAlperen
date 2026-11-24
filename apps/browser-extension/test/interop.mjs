// Interop test: this script plays the extension (noise.js) against the
// desktop app's responder (snow), over stdin/stdout with the native-messaging
// framing. Started by the Rust test `bridge::interop::noise_interop`.
//
// argv[2]: "pair" or "use". Prints "CODE <code>" on stderr after the
// handshake and exits 0 when every check passed.

import { Initiator, generateKeyPair, pairingCode, toBase64, fromBase64 } from '../noise.js';

const intent = process.argv[2] ?? 'pair';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

let buffered = Buffer.alloc(0);
const waiting = [];
process.stdin.on('data', (chunk) => {
  buffered = Buffer.concat([buffered, chunk]);
  pump();
});
process.stdin.on('end', () => {
  while (waiting.length) waiting.shift().reject(new Error('closed'));
});

function pump() {
  while (waiting.length && buffered.length >= 4) {
    const len = buffered.readUInt32LE(0);
    if (buffered.length < 4 + len) return;
    const frame = buffered.subarray(4, 4 + len);
    buffered = buffered.subarray(4 + len);
    waiting.shift().resolve(JSON.parse(decoder.decode(frame)));
  }
}

function next() {
  return new Promise((resolve, reject) => {
    waiting.push({ resolve, reject });
    pump();
  });
}

function send(obj) {
  const body = Buffer.from(JSON.stringify(obj));
  const len = Buffer.alloc(4);
  len.writeUInt32LE(body.length, 0);
  process.stdout.write(Buffer.concat([len, body]));
}

function check(cond, what) {
  if (!cond) {
    process.stderr.write(`FAIL ${what}\n`);
    process.exit(1);
  }
}

// A fixed static key per run is enough: the Rust side pairs it.
const s = await generateKeyPair();
const ini = new Initiator(s);
send({ t: 'hs', d: toBase64(await ini.writeMessage1(encoder.encode(JSON.stringify({ v: 1, intent })))) });
const m2 = await next();
check(m2.t === 'hs', `message 2 type ${JSON.stringify(m2)}`);
await ini.readMessage2(fromBase64(m2.d));
check(ini.rs.length === 32, 'app static key');
send({ t: 'hs', d: toBase64(await ini.writeMessage3(new Uint8Array(0))) });
const session = ini.session;
process.stderr.write(`CODE ${pairingCode(session.handshakeHash)}\n`);

let id = 0;
async function read() {
  const env = await next();
  check(env.t === 'm', `transport type ${JSON.stringify(env)}`);
  return JSON.parse(decoder.decode(await session.decrypt(fromBase64(env.d))));
}
async function call(req) {
  id += 1;
  const sealed = await session.encrypt(encoder.encode(JSON.stringify({ id, ...req })));
  send({ t: 'm', d: toBase64(sealed) });
  const r = await read();
  check(r.id === id, `reply id ${r.id} != ${id}`);
  return r;
}

const first = await read();
check(first.ok === true && first.paired === true, `pairing reply ${JSON.stringify(first)}`);

const status = await call({ op: 'status' });
check(status.ok === true && status.locked === false, `status ${JSON.stringify(status)}`);

const logins = await call({ op: 'logins', origin: 'https://www.site.com/login' });
check(logins.ok && logins.logins.length === 1 && logins.logins[0].username === 'ali', `logins ${JSON.stringify(logins)}`);
check(!('password' in logins.logins[0]), 'no password in list');

const other = await call({ op: 'logins', origin: 'https://evil.site.com' });
check(other.ok && other.logins.length === 0, 'other site gets nothing');

const fill = await call({ op: 'fill', origin: 'https://site.com', entry: '0:e1' });
check(fill.ok && fill.password === 'gizli', `fill ${JSON.stringify(fill)}`);

// Tampering: a flipped bit must be rejected by the app (connection ends).
const sealed = await session.encrypt(encoder.encode(JSON.stringify({ id: 99, op: 'status' })));
sealed[sealed.length - 1] ^= 1;
send({ t: 'm', d: toBase64(sealed) });
let closed = false;
try {
  await next();
} catch {
  closed = true;
}
check(closed, 'tampered message closes the connection');

process.stderr.write('OK\n');
process.exit(0);
