# Güncellemeler

LockAlperen, kurulu sürümün üzerine yeni sürümü kendisi kurabilir. Kullanıcının bir şey silmesi
ya da yeniden indirmesi gerekmez. Kasa dosyaları ve `%LOCALAPPDATA%` altındaki ayarlar
(`settings.json`, `recent.json`) olduğu gibi kalır.

> **Ön koşul:** Uygulama `LockAlperen_x.y.z_x64-setup.exe` ile **kurulmuş** olmalı. Derleme
> klasöründen tek başına çalıştırılan `.exe` kendini güncelleyemez: kurulum dosyası onu bulamaz.

## Kullanıcı ne görür

1. Uygulama açılınca (Ayarlar'da "Açılışta yeni sürümü denetle" açıksa, varsayılan **açık**)
   yeni sürüm olup olmadığına bakılır. İnternet yoksa sessizce geçilir.
2. Yeni sürüm varsa sağ altta bir bildirim çıkar: **Güncelle** / **Sonra**.
3. "Güncelle" dendiğinde kullanıcıya ne olacağı söylenir: kasa kilitlenir, kaydedilmemiş
   düzenlemeler kaybolur, uygulama yeniden açılır. Onaydan sonra kurulum dosyası indirilir ve
   **imzası doğrulanır**. Kasa ancak bundan sonra kilitlenir, pano temizlenir ve kurulum
   başlar. Uygulama kapanır, kurulum bitince yeniden açılır.
4. Ayarlar'da kullanılan sürüm görünür ve "Şimdi denetle" ile elle denetlenebilir.

## Güven zinciri

| Adım | Kontrol |
|---|---|
| `latest.json` alınır | Yalnızca HTTPS (eklenti `http` adresini reddeder). Adres sabit: `https://github.com/alperen-cpu/LockAlperen/releases/latest/download/latest.json`. Windows sertifika deposu kullanılır (`rustls-platform-verifier`); sistem proxy'si desteklenir |
| Sürüm karşılaştırılır | Yalnızca **daha yeni** sürüm kurulur (`allowDowngrades` kapalı) |
| İndirme adresi | Yalnızca `https://github.com/alperen-cpu/LockAlperen/releases/download/...` (`update::download_url_allowed`, testli). Kontrol hem denetimde hem kurulumdan önce yapılır |
| Kurulum dosyası | Minisign (Ed25519) imzası, uygulamanın **içine gömülü** açık anahtarla doğrulanır. İmza tutmazsa hiçbir şey diske yazılmaz ve çalıştırılmaz |
| Sürüm bağlama | İmzanın güvenilir yorumunda sürüm yazar ve bu, `latest.json`'daki sürümle aynı olmalıdır (`requireSignedVersion`). Böylece kurcalanmış bir `latest.json`, eski ama geçerli imzalı bir kurulumu "yeni sürüm" diye sunamaz |
| WebView | Adres, imza ya da dosya göremez ve veremez. Yalnızca "denetle" ve "bulduğunu kur" diyebilir (`check_update`, `install_update`). Eklentinin kendi JS komutlarına izin verilmez |
| Anahtar yokken | `pubkey` boşsa ağa hiç çıkılmaz ("Bu sürümde güncelleme anahtarı yok") |

Ayarlar `src-tauri/tauri.conf.json` → `plugins.updater` içindedir. Bunların gevşetilmediğini
`update::tests::shipped_updater_config_is_strict` testi kontrol eder.

**Korumadığı durumlar:**
- **Özel imza anahtarı ve parolası birlikte çalınırsa** saldırgan geçerli bir güncelleme
  üretebilir. Anahtar yalnızca GitHub Secrets'ta ve sahibinin yedeğinde durmalı.
- **GitHub hesabı ele geçirilirse** saldırgan sürüm yayınlayabilir. Ancak imzalı kurulum
  üretemez, çünkü anahtar repoda değil. Yine de Secrets'a erişebilir. Hesapta 2FA şarttır.
- **Windows kod imzası (Authenticode) yok.** SmartScreen, ilk kurulumda "tanınmayan uygulama"
  uyarısı verebilir. Güncelleme imzası bunun yerine geçmez.
- **Gizlilik:** Denetim isteği GitHub'a gider. GitHub ve ağ, LockAlperen kullanıldığını ve IP
  adresini görebilir. Kasa hakkında hiçbir bilgi gönderilmez. Ayarlar'dan kapatılabilir.

## Bir kerelik kurulum (proje sahibi)

1. **Repo herkese açık olmalı.** Uygulama Releases'tan parolasız indirir. Gizli bir repoda
   `latest.json` 404 döner ve güncelleme hiç görünmez.
2. İmza anahtarını üretin (parola sorar, **güçlü bir parola** verin):
   ```sh
   cd apps/desktop
   npx tauri signer generate -w %USERPROFILE%\.tauri\lockalperen.key
   ```
3. `lockalperen.key.pub` dosyasının **içeriğini** `src-tauri/tauri.conf.json` →
   `plugins.updater.pubkey` alanına yapıştırıp commit edin.
4. GitHub → Settings → Secrets and variables → Actions:
   - `TAURI_SIGNING_PRIVATE_KEY`: `lockalperen.key` dosyasının içeriği
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`: anahtarın parolası
5. `lockalperen.key` dosyasını ve parolasını **çevrimdışı bir yere yedekleyin** (ör. bir
   LockAlperen kasasına ek olarak). Anahtar kaybolursa kurulu kopyalar bir daha güncelleme
   alamaz; kullanıcıların yeni anahtarlı sürümü elle kurması gerekir.

## Sürüm yayınlama

```sh
cd apps/desktop
node scripts/set-version.mjs 0.2.0     # package.json, package-lock, tauri.conf, Cargo.toml/.lock
# CHANGELOG.md'yi güncelleyin, commit edip main'e alın
git tag v0.2.0
git push origin v0.2.0
```

`.github/workflows/release.yml` sırasıyla şunları yapar:
1. Etiketin üç sürüm dosyasıyla aynı olduğunu ve `pubkey`'in dolu olduğunu kontrol eder.
2. Testleri çalıştırır.
3. Kurulumu derleyip imzalar (`tauri.release.conf.json`: `createUpdaterArtifacts`).
4. **İmzayı uygulamadaki açık anahtarla doğrular** (`cargo run --example verify_release`).
   Böylece yanlış anahtarla imzalanmış, hiçbir kopyanın kuramayacağı bir sürüm yayınlanmaz.
5. `latest.json`'u yazar.
6. **Taslak (draft)** bir GitHub Release oluşturur.

Taslağı kontrol edip **Publish** dediğiniz anda kurulu kopyalar yeni sürümü görmeye başlar.
Taslakken hiçbir kopya onu görmez.

Sürüm numarası `MAJOR.MINOR.PATCH` olmalı (ör. `0.2.0`). Ön sürüm etiketleri (`-beta`)
desteklenmez.

## Doğrulananlar ve doğrulanmayanlar

- ✅ Birim testleri: indirme adresi izin listesi, anahtar yokken ağa çıkılmaması, sevk edilen
  yapılandırmanın sıkılığı, eski `settings.json`'un korunması.
- ✅ Yerelde, **geçici bir test anahtarıyla**: `tauri build` + `tauri.release.conf.json`,
  `.sig` dosyasını üretiyor ve imzaya sürümü yazıyor. `verify_release` doğru anahtarı kabul
  ediyor, başka anahtarı ve yanlış sürümü reddediyor.
- ⏳ **Gerçek bir güncellemenin baştan sona kurulması henüz denenmedi.** Bunun için repo herkese
  açık olmalı ve en az iki sürüm yayınlanmış olmalı. İlk deneme: `0.1.x` kurulu bir makinede
  `0.1.(x+1)`'i yayınlayıp uygulamayı açın. Bildirim çıkmalı, kurulum passive modda bitmeli,
  uygulama yeni sürümle açılmalı ve kasa açılabilmeli.
