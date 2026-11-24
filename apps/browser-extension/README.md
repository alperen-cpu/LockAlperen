# LockAlperen tarayıcı eklentisi (Chromium, yalnızca doldurma)

Chrome, Chromium, Brave ve Edge'de, LockAlperen masaüstü kasasındaki giriş bilgilerini açık
sitenin formuna doldurur. Kasaya yazmaz, ana parolayı hiçbir zaman sormaz. Kasa yalnızca masaüstü
uygulamasında açılır. Şimdilik yalnızca Linux masaüstü uygulamasıyla çalışır; Windows tarafı
(named pipe ve kayıt defteri) henüz yazılmadı.

## Kurulum (geliştirici modu)

1. LockAlperen'de **Ayarlar › Tarayıcı eklentisi › "Tarayıcı eklentisine izin ver"** seçeneğini
   açın. Uygulama, bulduğu tarayıcılar için kullanıcıya özel native messaging manifestini yazar.
   Ardından tarayıcıyı yeniden başlatın.
2. `chrome://extensions` › **Geliştirici modu** › **Paketlenmemiş öğe yükle** › bu klasör
   (`apps/browser-extension`). Eklenti kimliği `manifest.json` içindeki `key` ile sabittir:
   `lfhdblnhdfbfnkknmllnbndblidnlbed`. Manifest yalnızca bu kimliğe izin verir.
3. Eklenti simgesi › **Masaüstü uygulamasıyla eşleştir**. Eklentide ve masaüstündeki pencerede
   6 haneli bir kod görünür. Aynıysa masaüstünde **Eşleştir**'e basın.

Snap ve Flatpak tarayıcılar desteklenmez: korumalı alanları dışarıdaki bir programı
başlatamaz.

## Kullanım

- **Simge** (ya da `Ctrl+Shift+L`): Bu sitenin kayıtları listelenir. **Doldur** kullanıcı adını
  ve parolayı yazar. Kayıtta TOTP varsa **TOTP** düğmesi kodu panoya kopyalar.
- **`Alt+Shift+L`**: Sitede tek kayıt varsa doğrudan doldurur. Birden fazla kayıt varsa rozette
  sayıyı gösterir.
- Bir kayıt bir sitede ilk kez doldurulurken masaüstü uygulaması onay ister. "İzin ver" denirse o
  kayıt o sitede bir daha sorulmadan kullanılır. Bu izinler eşleştirmeyle birlikte silinir
  (Ayarlar › Tarayıcı eklentisi › Kaldır).

## Güvenlik tasarımı

Kurallar, rakiplerde son 10 yılda çıkan açıklardan türetildi
(`docs/research/rakipler-eklenti-2016-2026.md` §3; köşeli parantezler o listedeki kural
numaralarıdır).

| Konu | Uygulama | Hangi açığa karşı |
|---|---|---|
| Ağ portu | **Yok.** Tarayıcı › native host (uygulamanın kendi ikili dosyası, `--lav-nm-host`) › `$XDG_RUNTIME_DIR/<uygulama>/bridge.sock` (klasör 0700, soket 0600, `SO_PEERCRED` ile aynı kullanıcı kontrolü). [22] | KeePassHttp, KeePassRPC CVE-2020-16271/16272, Trend Micro CVE-2016-3987 |
| Kimlik doğrulama | **Noise_XX_25519_AESGCM_SHA256**. Uygulamada `snow`, eklentide yalnızca WebCrypto (`noise.js`). İki uygulama bir testle birbirine karşı sınanıyor (`noise_interop`). Süreç kimliğine hiç güvenilmez. [24–26] | 1Password CVE-2024-42219 (getppid), CVE-2022-29868 |
| Eşleştirme | El sıkışma özetinden 6 haneli kod iki tarafta gösterilir; kullanıcı masaüstünde onaylar. Araya giren bir saldırganın iki taraftaki özetleri farklı olur, kodlar tutmaz. Uygulamanın anahtarı eklentide sabitlenir. Başka bir anahtar gelirse eklenti hiçbir şey göndermez (`wrong_app`). [25] | KeePassHttp (anahtar açık metin gidiyordu) |
| Eklentinin anahtarı | IndexedDB'de, **dışa aktarılamaz** `CryptoKey` olarak. `chrome.storage` kullanılmaz, kasa verisi hiç saklanmaz. [20] | Bitwarden CVE-2023-27706 sınıfı |
| Köken | Sayfanın kökenini tarayıcı verir (`tab.url`, WHATWG `URL`), sayfa içeriği değil. Eşleşmeye masaüstü karar verir. **Tam köken**: şema, alan adı ve port aynı olmalı. Alt alan adları eşleşmez. Tek esneklik `www.` ile çıplak alan adının aynı sayılması ve http kaydının aynı adresin https sayfasına doldurulabilmesi (tersi değil). Bu kurallar `bridge/origin.rs` testlerinde. [1–5] | LastPass 2016 (URL ayrıştırma), Bitwarden ve Proton Pass alt alan adları, Tóth 2025 |
| Çerçeve | Yalnızca üst çerçeve (`frameIds: [0]`). Doldurmadan hemen önce `location.origin` ve `self.origin` yeniden kontrol edilir; sandbox (`null`) kökenlere doldurulmaz. [6, 7] | Bitwarden iframe, KeePassXC-Browser CVE-2025-65203 |
| Kullanıcı eylemi | Sayfa açılınca otomatik doldurma **yok**. Doldurma yalnızca açılır pencereden ya da klavye kısayolundan yapılır; ikisi de sayfanın DOM'u dışında olduğu için sayfa onları gizleyemez ya da üstüne bir şey çizemez. Sayfaya hiçbir arayüz enjekte edilmez. [9–11] | DOM tabanlı eklenti clickjacking (Tóth, DEF CON 33), Keeper 2016/2017 |
| Görünür alan | Yalnızca görünür, etkin, ekranda olan ve üstünde başka bir öğe bulunmayan alanlara doldurulur (opaklık, `visibility`, `aria-hidden`/`inert` ve `elementFromPoint` kontrolleri). [12] | Gizli form ile toplu bilgi toplama (sweep), izleyicilerin bilgi toplaması |
| TOTP | Ayrı bir düğme; giriş bilgisiyle birlikte gönderilmez. [13] | Tóth 2025 (TOTP sızıntısı) |
| Yüzey | `externally_connectable` yok, `onMessageExternal` yok, içerik betiği yok, `web_accessible_resources` yok. İzinler: `activeTab`, `scripting`, `nativeMessaging`. CSP `script-src 'self'`; veriler yalnızca `textContent` ile yazılır. [16–21] | LastPass websiteConnector, Proton Pass `externally_connectable` |
| Köprü komutları | `status`, `logins`, `fill`, `totp`. Dosya açma, dışa aktarma, ayar değiştirme ya da "tüm kayıtlar" yok. İstekler en çok 4 KiB, tipli ve bilinmeyen alanları reddeden ayrıştırıcıdan geçer. 10 saniyede en çok 40 istek. [18, 27, 30] | LastPass `openattach` (uzaktan kod çalıştırma), KeePassXC CVE-2026-118673 |
| Kilit | Kasa kilitliyken yalnızca "kilitli" yanıtı döner. Kilit uygulamada açılır. Eklenti ana parolayı istemez. [29] | Eklenti taklidiyle ana parola avı |
| Masaüstü onayı | Eşleştirme ve her (kayıt, site) için ilk doldurma, ana pencere öne getirilerek bir onay penceresiyle sorulur. Aynı anda yalnızca bir pencere açılır (`busy`). [14, 32] | |

**Bilinen sınırlar:**
- Doldurulan değer sayfanın JavaScript'ine görünür; bu, her parola yöneticisinde böyledir.
- Eklentinin servis çalışanındaki JS dizeleri silinemez (çöp toplayıcı).
- `bridge.json`'daki uygulama anahtarını aynı kullanıcıyla çalışan zararlı yazılım okuyabilir.
  Bu anahtarla uygulamayı taklit edebilir, ama kasayı açamaz.
- Eşleştirme durumu kasa anahtarıyla MAC'lenmiyor [33, SHOULD].
- Windows desteği yok.

## Test

```sh
cd apps/desktop/src-tauri
LAV_REQUIRE_NODE=1 cargo test bridge   # köken, depo, protokol ve JS↔Rust Noise testi
```

`test/interop.mjs`, `noise.js`'yi Node'da eklenti olarak çalıştırır. Gerçek protokolü `snow`
yanıtlayıcısına karşı sınar: el sıkışma, eşleştirme kodu, istekler ve değiştirilmiş bir mesajın
reddedilmesi.
