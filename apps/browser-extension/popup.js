// Popup: shows the state for the active tab and sends the user's choice to
// the service worker. Only textContent is used for data (no innerHTML).

const main = document.getElementById('main');
const originBox = document.getElementById('origin');
const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

const ERRORS = {
  no_host:
    'Masaüstü bağlantısı kurulu değil. LockAlperen\'de Ayarlar › Tarayıcı eklentisi › "Bağlantıyı aç" deyin, sonra tarayıcıyı yeniden başlatın.',
  not_running: 'LockAlperen masaüstü uygulaması çalışmıyor. Uygulamayı açın.',
  disabled: 'Masaüstü uygulamasında tarayıcı eklentisi kapalı (Ayarlar › Tarayıcı eklentisi).',
  wrong_app:
    'Bağlanılan uygulama eşleştirilen LockAlperen değil. Uygulamayı yeniden kurduysanız yeniden eşleştirin; kurmadıysanız bu bir saldırı olabilir.',
  rejected: 'Eşleştirme masaüstünde reddedildi.',
  denied: 'İstek masaüstünde reddedildi.',
  busy: 'Masaüstünde başka bir onay penceresi açık.',
  rate: 'Çok fazla istek; biraz bekleyin.',
  no_match: 'Bu kayıt bu siteyle eşleşmiyor.',
  no_totp: 'Bu kayıtta TOTP yok.',
  locked: 'Kasa kilitli. LockAlperen\'de kasanızı açın.',
  no_page: 'Bu sayfada doldurma yapılmaz (yalnızca http/https siteler).',
  closed: 'Bağlantı kapandı. Tekrar deneyin.',
  version: 'Masaüstü uygulaması bu eklenti sürümünü desteklemiyor; ikisini de güncelleyin.',
};

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v;
    else if (k === 'onclick') e.addEventListener('click', v);
    else e[k] = v;
  }
  for (const c of children) e.append(c);
  return e;
}

function show(...nodes) {
  main.replaceChildren(...nodes);
}

function setOrigin(origin) {
  if (origin) {
    originBox.replaceChildren('Site: ', el('b', { textContent: origin }));
    originBox.hidden = false;
  } else {
    originBox.hidden = true;
  }
}

const send = (msg) => chrome.runtime.sendMessage({ ...msg, tabId: tab.id });

let poll = null;

async function refresh() {
  const st = await send({ op: 'state' });
  setOrigin(st.origin);
  clearTimeout(poll);
  switch (st.status) {
    case 'unpaired':
      show(
        el('p', { textContent: 'Bu tarayıcı henüz LockAlperen ile eşleştirilmedi.' }),
        el('button', {
          class: 'primary',
          textContent: 'Masaüstü uygulamasıyla eşleştir',
          onclick: async () => {
            await send({ op: 'pair' });
            refresh();
          },
        }),
      );
      return;
    case 'pairing':
      show(
        el('p', { textContent: 'Masaüstündeki pencerede aynı kodu görüyorsanız orada "Eşleştir"e basın:' }),
        el('div', { class: 'code', textContent: st.code ?? '··· ···' }),
        el('p', { class: 'note', textContent: 'Kod farklıysa "Reddet"e basın.' }),
      );
      poll = setTimeout(refresh, 400);
      return;
    case 'pair_failed':
      show(
        el('p', { class: 'warn', textContent: ERRORS[st.error] ?? `Eşleştirilemedi (${st.error}).` }),
        el('button', {
          textContent: 'Tekrar dene',
          onclick: async () => {
            await send({ op: 'pair_reset' });
            refresh();
          },
        }),
      );
      return;
    case 'locked':
      show(el('p', { class: 'warn', textContent: ERRORS.locked }));
      return;
    case 'no_page':
      show(el('p', { class: 'muted', textContent: ERRORS.no_page }));
      return;
    case 'ready':
      showLogins(st);
      return;
    default: {
      const nodes = [el('p', { class: 'warn', textContent: ERRORS[st.error] ?? `Hata: ${st.error}` })];
      if (st.error === 'wrong_app') {
        nodes.push(el('button', { textContent: 'Yeniden eşleştir', onclick: async () => { await send({ op: 'pair' }); refresh(); } }));
      }
      show(...nodes);
    }
  }
}

function showLogins(st) {
  if (!st.logins.length) {
    show(el('p', { class: 'muted', textContent: 'Bu site için kasada kayıt yok.' }));
    return;
  }
  const status = el('p', { class: 'note' });
  const list = el(
    'ul',
    {},
    ...st.logins.map((l) => {
      const fillBtn = el('button', {
        class: 'primary',
        textContent: 'Doldur',
        onclick: async () => {
          fillBtn.disabled = true;
          status.textContent = 'Masaüstünde onay gerekebilir…';
          const r = await send({ op: 'fill', entry: l.id });
          fillBtn.disabled = false;
          if (r.ok) {
            window.close();
          } else {
            status.textContent =
              r.reason === 'no_field'
                ? 'Sayfada görünür bir giriş alanı bulunamadı.'
                : r.reason === 'origin'
                  ? 'Sayfa değişti; doldurulmadı.'
                  : ERRORS[r.error] ?? `Doldurulamadı (${r.error ?? r.reason}).`;
          }
        },
      });
      const row = [el('div', { class: 'who' }, el('div', { class: 'title', textContent: l.title || '(başlıksız)' }), el('div', { class: 'user', textContent: l.username }))];
      if (l.hasTotp) {
        const totpBtn = el('button', {
          textContent: 'TOTP',
          title: 'Tek kullanımlık kodu panoya kopyala',
          onclick: async () => {
            const r = await send({ op: 'totp', entry: l.id });
            if (r.ok) {
              await navigator.clipboard.writeText(r.code);
              status.textContent = 'Kod kopyalandı (30 sn içinde geçersiz olur).';
            } else {
              status.textContent = ERRORS[r.error] ?? `Kod alınamadı (${r.error}).`;
            }
          },
        });
        row.push(totpBtn);
      }
      row.push(fillBtn);
      return el('li', {}, ...row);
    }),
  );
  show(list, status);
}

refresh();
