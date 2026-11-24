// The extension's long-term state, in IndexedDB (never chrome.storage):
// - "static": our X25519 key pair. The private key is a non-extractable
//   CryptoKey: scripts can use it but cannot read its bytes.
// - "app": the desktop app's public key, pinned at pairing. A later session
//   with any other key is refused (another program on the socket).
// No vault data is ever stored here.

import { generateKeyPair } from './noise.js';

const DB = 'lockalperen';
const STORE = 'keys';

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx(mode, fn) {
  const db = await open();
  try {
    return await new Promise((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const req = fn(t.objectStore(STORE));
      t.oncomplete = () => resolve(req?.result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  } finally {
    db.close();
  }
}

const get = (key) => tx('readonly', (s) => s.get(key));
const put = (key, value) => tx('readwrite', (s) => s.put(value, key));
const del = (key) => tx('readwrite', (s) => s.delete(key));

/** Our static key pair, made on first use. */
export async function staticKey() {
  const have = await get('static');
  if (have?.privateKey && have?.publicKey) return have;
  const kp = await generateKeyPair(false);
  await put('static', kp);
  return kp;
}

export async function pinnedAppKey() {
  return (await get('app')) ?? null;
}

export async function pinAppKey(publicKey) {
  await put('app', publicKey);
}

/** Forget the pairing (the app revoked it or the user re-pairs). */
export async function forgetPairing() {
  await del('app');
}
