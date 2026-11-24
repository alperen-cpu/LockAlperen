// LockAlperen extension, service worker.
//
// Rules (docs/research/rakipler-eklenti-2016-2026.md §3, numbers in brackets):
// - Only the popup talks to us; no content scripts, no externally_connectable,
//   no onMessageExternal [16, 17].
// - The page origin comes from the browser (tab.url via the WHATWG URL
//   parser), never from page content [1, 2]. The desktop app decides which
//   entries match it [5].
// - Fill only after a user action outside the page (popup button or the
//   keyboard shortcut) [9, 10], only into the top frame [6], only when the
//   frame still has the same origin and is not sandboxed [7], only into
//   visible fields [12]. TOTP is its own action [13].
// - Secrets are kept only for the fill and never stored [20].
// - All traffic to the app is Noise-encrypted after a paired handshake; no
//   network ports [22-26]. We never ask for the master password [29].

import { Initiator, pairingCode, toBase64, fromBase64, equalBytes } from './noise.js';
import { staticKey, pinnedAppKey, pinAppKey, forgetPairing } from './keys.js';

const HOST = 'com.alperen.lockalperen';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

class BridgeError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/** A native-messaging port with an awaitable inbox. */
function openPort() {
  const port = chrome.runtime.connectNative(HOST);
  const queue = [];
  const waiters = [];
  let closed = null;
  port.onMessage.addListener((m) => {
    if (waiters.length) waiters.shift().resolve(m);
    else queue.push(m);
  });
  port.onDisconnect.addListener(() => {
    const why = chrome.runtime.lastError?.message ?? '';
    closed = new BridgeError(/native messaging host/i.test(why) ? 'no_host' : 'closed');
    while (waiters.length) waiters.shift().reject(closed);
  });
  return {
    port,
    next() {
      if (queue.length) return Promise.resolve(queue.shift());
      if (closed) return Promise.reject(closed);
      return new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    },
    get closed() {
      return closed !== null;
    },
    close() {
      try {
        port.disconnect();
      } catch {
        // already gone
      }
      closed ??= new BridgeError('closed');
    },
  };
}

class Conn {
  constructor(link, session) {
    this.link = link;
    this.session = session;
    this.nextId = 1;
    this.chain = Promise.resolve();
  }

  get closed() {
    return this.link.closed;
  }

  close() {
    this.link.close();
  }

  async read() {
    const env = await this.link.next();
    if (env?.t === 'err') throw new BridgeError(String(env.e));
    if (env?.t !== 'm' || typeof env.d !== 'string') throw new BridgeError('protocol');
    return JSON.parse(decoder.decode(await this.session.decrypt(fromBase64(env.d))));
  }

  /** One request at a time (the app answers in order). */
  call(op, extra = {}) {
    const run = async () => {
      const id = this.nextId++;
      const body = { ...extra, id, op };
      const sealed = await this.session.encrypt(encoder.encode(JSON.stringify(body)));
      this.link.port.postMessage({ t: 'm', d: toBase64(sealed) });
      const r = await this.read();
      if (r.id !== id) throw new BridgeError('protocol');
      if (r.ok === false && (r.error === 'not_paired' || r.error === 'disabled')) {
        if (r.error === 'not_paired') await forgetPairing();
        this.close();
        throw new BridgeError(r.error);
      }
      return r;
    };
    const p = this.chain.then(run, run);
    this.chain = p.catch(() => {});
    return p;
  }
}

async function handshake(intent, onCode) {
  const s = await staticKey();
  const link = openPort();
  try {
    const ini = new Initiator(s);
    const hello = encoder.encode(JSON.stringify({ v: 1, intent }));
    link.port.postMessage({ t: 'hs', d: toBase64(await ini.writeMessage1(hello)) });
    const m2 = await link.next();
    if (m2?.t === 'err') throw new BridgeError(String(m2.e));
    if (m2?.t !== 'hs' || typeof m2.d !== 'string') throw new BridgeError('protocol');
    await ini.readMessage2(fromBase64(m2.d));
    if (intent === 'use') {
      const pinned = await pinnedAppKey();
      if (!pinned) throw new BridgeError('not_paired');
      // Another program in the app's place: never send it anything.
      if (!equalBytes(pinned, ini.rs)) throw new BridgeError('wrong_app');
    }
    link.port.postMessage({ t: 'hs', d: toBase64(await ini.writeMessage3(new Uint8Array(0))) });
    if (onCode) onCode(pairingCode(ini.session.handshakeHash));
    const conn = new Conn(link, ini.session);
    const first = await conn.read();
    if (!first.ok) {
      if (first.error === 'not_paired') await forgetPairing();
      throw new BridgeError(String(first.error ?? 'rejected'));
    }
    if (intent === 'pair') await pinAppKey(ini.rs);
    return conn;
  } catch (e) {
    link.close();
    throw e instanceof BridgeError ? e : new BridgeError('protocol');
  }
}

let conn = null;
let connecting = null;
let pairing = null; // { code, error, done }

async function getConn() {
  if (conn && !conn.closed) return conn;
  conn = null;
  connecting ??= handshake('use').finally(() => {
    connecting = null;
  });
  conn = await connecting;
  return conn;
}

/** The page's origin as the browser reports it; null for non-web pages. */
function pageOrigin(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    if (u.username || u.password) return null;
    return u.origin;
  } catch {
    return null;
  }
}

async function stateFor(tab) {
  if (pairing && !pairing.done) {
    return pairing.error
      ? { status: 'pair_failed', error: pairing.error }
      : { status: 'pairing', code: pairing.code };
  }
  if (!(await pinnedAppKey())) return { status: 'unpaired' };
  const origin = pageOrigin(tab?.url ?? '');
  try {
    const c = await getConn();
    const st = await c.call('status');
    if (st.locked) return { status: 'locked', origin };
    if (!origin) return { status: 'no_page' };
    const r = await c.call('logins', { origin });
    if (!r.ok) return { status: 'error', error: r.error, origin };
    return { status: 'ready', origin: r.origin, logins: r.logins };
  } catch (e) {
    const code = e?.code ?? 'error';
    if (code === 'not_paired') return { status: 'unpaired' };
    return { status: 'error', error: code, origin };
  }
}

/**
 * Runs in the page (isolated world, top frame only). Fills only if the
 * frame is still `expected` and the fields are really visible.
 */
function fillInPage(expected, username, password) {
  if (window.top !== window || location.origin !== expected || self.origin !== expected) {
    return { ok: false, reason: 'origin' };
  }
  const visible = (el) => {
    if (!el || el.disabled || el.readOnly || !el.isConnected) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 4 || r.height < 4) return false;
    if (r.bottom < 0 || r.right < 0 || r.top > innerHeight || r.left > innerWidth) return false;
    if (el.closest('[aria-hidden="true"],[hidden],[inert]')) return false;
    for (let n = el; n; n = n.parentElement) {
      const s = getComputedStyle(n);
      if (s.display === 'none' || s.visibility !== 'visible' || parseFloat(s.opacity) < 0.2) return false;
    }
    // Something drawn over the field (an overlay or a decoy) is refused; the
    // field's own wrapper (a floating label) is fine.
    const top = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    const wrap = el.parentElement?.parentElement ?? el.parentElement;
    return Boolean(top) && (top === el || top.control === el || (wrap !== null && wrap.contains(top)));
  };
  const textLike = (el) =>
    el instanceof HTMLInputElement &&
    ['text', 'email', 'tel', ''].includes(el.type) &&
    !/one-time-code/i.test(el.autocomplete);
  const set = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };

  const active = document.activeElement instanceof HTMLInputElement ? document.activeElement : null;
  const passwords = [...document.querySelectorAll('input[type=password]')].filter(visible);
  let pw = active && active.type === 'password' && visible(active) ? active : null;
  if (!pw && active?.form) pw = passwords.find((p) => p.form === active.form) ?? null;
  if (!pw) pw = passwords[0] ?? null;

  let user = active && textLike(active) && visible(active) ? active : null;
  if (!user) {
    const scope = pw?.form ?? document;
    const candidates = [...scope.querySelectorAll('input')].filter((el) => textLike(el) && visible(el));
    if (pw) {
      // The last text field before the password field.
      const before = candidates.filter(
        (el) => el.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING,
      );
      user = before[before.length - 1] ?? null;
    } else {
      user =
        candidates.find((el) => /username|email/i.test(el.autocomplete)) ??
        (candidates.length === 1 ? candidates[0] : null);
    }
  }
  if (!pw && !user) return { ok: false, reason: 'no_field' };
  if (user && username) set(user, username);
  if (pw) set(pw, password);
  return { ok: true, user: Boolean(user && username), password: Boolean(pw) };
}

async function fill(tabId, entry) {
  const tab = await chrome.tabs.get(tabId);
  const origin = pageOrigin(tab.url ?? '');
  if (!origin) throw new BridgeError('no_page');
  const c = await getConn();
  const r = await c.call('fill', { origin, entry });
  if (!r.ok) throw new BridgeError(r.error);
  let username = r.username;
  let password = r.password;
  r.username = r.password = null;
  try {
    const [res] = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      func: fillInPage,
      args: [origin, username, password],
    });
    return res?.result ?? { ok: false, reason: 'script' };
  } finally {
    username = password = null;
  }
}

async function totp(tabId, entry) {
  const tab = await chrome.tabs.get(tabId);
  const origin = pageOrigin(tab.url ?? '');
  if (!origin) throw new BridgeError('no_page');
  const r = await (await getConn()).call('totp', { origin, entry });
  if (!r.ok) throw new BridgeError(r.error);
  return { ok: true, code: r.code };
}

function startPairing() {
  if (pairing && !pairing.done && !pairing.error) return;
  conn?.close();
  conn = null;
  pairing = { code: null, error: null, done: false };
  const mine = pairing;
  handshake('pair', (code) => {
    mine.code = code;
  }).then(
    (c) => {
      conn = c;
      mine.done = true;
    },
    (e) => {
      mine.error = e?.code ?? 'error';
    },
  );
}

async function handle(msg) {
  switch (msg?.op) {
    case 'state':
      return stateFor(await chrome.tabs.get(msg.tabId));
    case 'pair':
      startPairing();
      return { ok: true };
    case 'pair_reset':
      pairing = null;
      return { ok: true };
    case 'fill':
      return fill(msg.tabId, String(msg.entry));
    case 'totp':
      return totp(msg.tabId, String(msg.entry));
    default:
      throw new BridgeError('bad_request');
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only our own popup.
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL('popup.html'))) {
    return false;
  }
  handle(msg).then(sendResponse, (e) => sendResponse({ ok: false, error: e?.code ?? 'error' }));
  return true;
});

async function badge(tabId, text) {
  await chrome.action.setBadgeText({ tabId, text });
  setTimeout(() => chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {}), 4000);
}

// Keyboard shortcut: fills only when this site has exactly one entry.
chrome.commands.onCommand.addListener(async (command, tab) => {
  if (command !== 'fill-login' || !tab?.id) return;
  try {
    const st = await stateFor(tab);
    if (st.status === 'ready' && st.logins.length === 1) {
      const res = await fill(tab.id, st.logins[0].id);
      await badge(tab.id, res.ok ? 'OK' : '!');
    } else {
      await badge(tab.id, st.status === 'ready' ? String(st.logins.length) : '!');
    }
  } catch {
    await badge(tab.id, '!');
  }
});
