// Noise_XX_25519_AESGCM_SHA256, initiator side, WebCrypto only (no
// third-party code). The responder is `snow` in the desktop app; the two are
// tested against each other (apps/desktop/src-tauri: `noise_interop`).
//
// Spec: https://noiseprotocol.org/noise.html (rev 34). Sections cited below.

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();

export const PROTOCOL = 'Noise_XX_25519_AESGCM_SHA256';
export const PROLOGUE = encoder.encode('lockalperen-bridge-v1');
const DHLEN = 32;
const HASHLEN = 32;
const TAGLEN = 16;
// §5.1: n = 2^64-1 is reserved; stop before it.
const MAX_NONCE = (1n << 64n) - 1n;

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

async function sha256(data) {
  return new Uint8Array(await subtle.digest('SHA-256', data));
}

async function hmac(key, data) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}

// §4.3 HKDF with two outputs.
async function hkdf2(chainingKey, ikm) {
  const temp = await hmac(chainingKey, ikm);
  const out1 = await hmac(temp, Uint8Array.of(1));
  const out2 = await hmac(temp, concat(out1, Uint8Array.of(2)));
  return [out1, out2];
}

/** A new X25519 key pair. The private key never leaves WebCrypto. */
export async function generateKeyPair(extractable = false) {
  const kp = await subtle.generateKey({ name: 'X25519' }, extractable, ['deriveBits']);
  const publicKey = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  return { privateKey: kp.privateKey, publicKey };
}

async function dh(privateKey, publicBytes) {
  if (publicBytes.length !== DHLEN) throw new Error('bad public key');
  const pub = await subtle.importKey('raw', publicBytes, { name: 'X25519' }, true, []);
  return new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pub }, privateKey, 256));
}

// §5.1 CipherState with the AESGCM nonce of §12.6.
class CipherState {
  async init(k) {
    this.n = 0n;
    this.key = k
      ? await subtle.importKey('raw', k.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt'])
      : null;
  }

  iv() {
    const iv = new Uint8Array(12);
    new DataView(iv.buffer).setBigUint64(4, this.n, false);
    return iv;
  }

  async encrypt(ad, plaintext) {
    if (!this.key) return plaintext;
    if (this.n >= MAX_NONCE) throw new Error('nonce exhausted');
    const c = await subtle.encrypt(
      { name: 'AES-GCM', iv: this.iv(), additionalData: ad, tagLength: 128 },
      this.key,
      plaintext,
    );
    this.n += 1n;
    return new Uint8Array(c);
  }

  async decrypt(ad, ciphertext) {
    if (!this.key) return ciphertext;
    if (this.n >= MAX_NONCE) throw new Error('nonce exhausted');
    // Throws on a bad tag; the nonce then does not advance (§5.1).
    const p = await subtle.decrypt(
      { name: 'AES-GCM', iv: this.iv(), additionalData: ad, tagLength: 128 },
      this.key,
      ciphertext,
    );
    this.n += 1n;
    return new Uint8Array(p);
  }
}

// §5.2 SymmetricState.
class SymmetricState {
  async init(protocolName) {
    const name = encoder.encode(protocolName);
    this.h = name.length <= HASHLEN ? concat(name, new Uint8Array(HASHLEN - name.length)) : await sha256(name);
    this.ck = this.h;
    this.cs = new CipherState();
    await this.cs.init(null);
  }

  async mixKey(ikm) {
    const [ck, k] = await hkdf2(this.ck, ikm);
    this.ck = ck;
    await this.cs.init(k);
  }

  async mixHash(data) {
    this.h = await sha256(concat(this.h, data));
  }

  async encryptAndHash(plaintext) {
    const c = await this.cs.encrypt(this.h, plaintext);
    await this.mixHash(c);
    return c;
  }

  async decryptAndHash(ciphertext) {
    const p = await this.cs.decrypt(this.h, ciphertext);
    await this.mixHash(ciphertext);
    return p;
  }

  async split() {
    const [k1, k2] = await hkdf2(this.ck, new Uint8Array(0));
    const c1 = new CipherState();
    const c2 = new CipherState();
    await c1.init(k1);
    await c2.init(k2);
    return [c1, c2];
  }
}

/** Transport after the handshake (§5.3 Split: initiator sends with c1). */
export class Session {
  constructor(send, recv, handshakeHash, remoteStatic) {
    this.sendCs = send;
    this.recvCs = recv;
    this.handshakeHash = handshakeHash;
    this.remoteStatic = remoteStatic;
  }

  encrypt(plaintext) {
    return this.sendCs.encrypt(new Uint8Array(0), plaintext);
  }

  decrypt(ciphertext) {
    return this.recvCs.decrypt(new Uint8Array(0), ciphertext);
  }
}

/**
 * XX (§7.5):
 *   -> e
 *   <- e, ee, s, es
 *   -> s, se
 */
export class Initiator {
  /** @param s {{privateKey: CryptoKey, publicKey: Uint8Array}} our static key */
  constructor(s) {
    this.s = s;
    this.step = 0;
  }

  async writeMessage1(payload) {
    if (this.step !== 0) throw new Error('handshake order');
    this.ss = new SymmetricState();
    await this.ss.init(PROTOCOL);
    await this.ss.mixHash(PROLOGUE);
    this.e = await generateKeyPair();
    await this.ss.mixHash(this.e.publicKey);
    const c = await this.ss.encryptAndHash(payload);
    this.step = 1;
    return concat(this.e.publicKey, c);
  }

  async readMessage2(message) {
    if (this.step !== 1) throw new Error('handshake order');
    if (message.length < DHLEN + DHLEN + TAGLEN + TAGLEN) throw new Error('short message');
    this.re = message.slice(0, DHLEN);
    await this.ss.mixHash(this.re);
    await this.ss.mixKey(await dh(this.e.privateKey, this.re));
    const rs = await this.ss.decryptAndHash(message.slice(DHLEN, DHLEN + DHLEN + TAGLEN));
    this.rs = rs;
    await this.ss.mixKey(await dh(this.e.privateKey, rs));
    const payload = await this.ss.decryptAndHash(message.slice(DHLEN + DHLEN + TAGLEN));
    this.step = 2;
    return payload;
  }

  async writeMessage3(payload) {
    if (this.step !== 2) throw new Error('handshake order');
    const c1 = await this.ss.encryptAndHash(this.s.publicKey);
    await this.ss.mixKey(await dh(this.s.privateKey, this.re));
    const c2 = await this.ss.encryptAndHash(payload);
    const [send, recv] = await this.ss.split();
    this.session = new Session(send, recv, this.ss.h, this.rs);
    this.step = 3;
    // The ephemeral key is not needed any more.
    this.e = null;
    return concat(c1, c2);
  }
}

/** The 6-digit code both sides show (same rule as conn.rs `pairing_code`). */
export function pairingCode(handshakeHash) {
  const n = new DataView(handshakeHash.buffer, handshakeHash.byteOffset, 4).getUint32(0, false) % 1000000;
  const s = String(n).padStart(6, '0');
  return `${s.slice(0, 3)} ${s.slice(3)}`;
}

export function toBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(text) {
  const s = atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function equalBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
