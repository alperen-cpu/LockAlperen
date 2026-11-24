# Password-manager browser extension / autofill / bridge / sync vulnerabilities, 2016–2026

Research input for the LockAlperen browser extension (Rust + Tauri 2 desktop app, extension over native messaging).
Compiled 2026-11-24 from web research. Every row was checked against a primary or reputable source (NVD/MITRE, vendor advisory, GitHub advisory, researcher write-up, or major security press). Markers:

- **[V]**: verified against a primary source (NVD, vendor advisory, GitHub advisory, or the researcher's own write-up).
- **[P]**: verified only through reputable secondary press. The primary source was not readable (for example a vendor page returned 403, or the Project Zero tracker was not fetched).
- **[U]**: not verified. The underlying claim may be true, but I found no primary confirmation; kept for completeness.
- "no CVE" means none was found. No CVE number in this file was invented; IDs appear only where NVD/MITRE or a vendor lists them.

Background research (pre-2016, cited only for context): Silver, Jana, Boneh, Chen, Jackson, *Password Managers: Attacks and Defenses*, USENIX Security 2014 (https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/silver) introduced "sweep" attacks: a network attacker injects hidden login forms or iframes for many sites and harvests whatever is auto-filled without user interaction. Stock & Johns, *Protecting users against XSS-based password manager abuse*, AsiaCCS 2014 (https://notify.cispa.uni-saarland.de/papers/stock2014protecting.pdf) showed that XSS on any page of a site can read auto-filled passwords. They proposed filling a nonce and swapping in the real password only on submission, and a 2025 follow-up (https://arxiv.org/abs/2509.02289) re-implemented the idea for Firefox.

---

## 1. Master table

| # | Product | Year | ID | Vulnerability class | Description | Precondition | Source URL |
|---|---|---|---|---|---|---|---|
| 1 | LastPass | 2016 | no CVE [V] | URL parsing / origin confusion | Autofill code parsed the URL with a faulty regex. A URL such as `attacker.com/@twitter.com/@x.php` made the extension believe it was on twitter.com and fill Twitter credentials. Fixed in under a day. | Victim visits an attacker URL with autofill enabled | https://labs.detectify.com/2016/07/27/how-i-made-lastpass-give-me-all-your-passwords |
| 2 | LastPass (Firefox) | 2016 | no CVE [P] | Extension message hijacking | Tavis Ormandy: a malicious page could hijack messages of the LastPass Firefox add-on, enabling full compromise. Fixed in 4.1.21a. | Visit malicious page | https://news.softpedia.com/news/two-vulnerabilities-affect-lastpass-both-allow-full-password-compromise-506677.shtml |
| 3 | LastPass (Chrome/Firefox/Edge) | 2017 | no CVE [V] | Content script proxies unauthenticated page messages | The `websiteConnector.js` content script forwarded unauthenticated messages from web pages to privileged extension code. Unprivileged pages could drive internal RPCs and steal passwords. | Visit malicious page | https://blog.lastpass.com/posts/security-update-for-the-lastpass-extension |
| 4 | LastPass "binary component" | 2017 | no CVE [P] | Extension → native code bridge → RCE | Same RPC exposure: if the native "binary component" was installed (default for IE/Firefox), the `openattach` command executed arbitrary code (calc.exe PoC in two lines of JS). | Binary component installed; visit malicious page | https://www.pcworld.com/article/406227/lastpass-is-scrambling-to-fix-another-serious-vulnerability.html |
| 5 | LastPass (Firefox 3.3.2) | 2017 | no CVE [P] | Page-to-extension privilege confusion | A second Ormandy bug in the legacy Firefox add-on let web pages extract stored passwords. | Visit malicious page | https://www.theregister.com/2017/03/21/lastpass_vulnerabilities/ |
| 6 | LastPass (Chrome/Opera) | 2019 | no CVE [P] | Popup/clickjacking, cached-credential leak across sites | Ormandy: a malicious page could open popup windows and get the extension to reveal the username and password last filled on the previous site (cached state not bound to origin). Fixed in 4.33.0. | Visit malicious page after using autofill elsewhere | https://www.theregister.com/2019/09/16/lastpass_vulnerability/ |
| 7 | LastPass (cloud) | 2022 | no CVE [V] | Cloud sync: unencrypted metadata | Stolen vault backups held website **URLs in plaintext**. Usernames, passwords and notes were encrypted. Plaintext URLs let attackers select high-value targets (crypto). | Breach of vendor backup storage | https://blog.lastpass.com/posts/notice-of-security-incident |
| 8 | LastPass (cloud) | 2022 | no CVE [P] | Weak / non-upgraded KDF | Many older accounts still used 5,000, 500 or even 1 PBKDF2 iteration while the new default was 100,100. Offline cracking of stolen vaults became feasible. Followed by over 150 crypto thefts that researchers linked to the breach. | Stolen vault + weak master password + legacy iteration count | https://mjtsai.com/blog/?p=37963 (quotes Palant; also Graham Cluley "LostPass") ; https://krebsonsecurity.com/2023/09/experts-fear-crooks-are-cracking-keys-stolen-in-lastpass-breach/ |
| 9 | LastPass (infra) | 2022 | no CVE [P] | Key custody / insider endpoint | Root cause: a keylogger on a senior DevOps engineer's home PC (reportedly via an old Plex vulnerability) captured the master password used to reach the vault-backup decryption keys. | Compromise of a privileged employee's endpoint | https://9to5mac.com/2023/02/27/lastpass-devops-engineers-hacked/ |
| 10 | Keeper extension | 2016 | no CVE [P] | Privileged code injection / clickjacking | Ormandy reported that a site could inject into the Keeper extension's privileged context and fake user input to steal passwords. | Visit malicious page | https://www.securityweek.com/google-researcher-finds-critical-flaw-keeper-password-manager/ |
| 11 | Keeper extension 11.3 (bundled with Windows 10) | 2017 | no CVE [P] | Regression of #10: injection + clickjacking | The same bug returned, so a site could steal any stored password (Twitter PoC). Keeper shipped 11.4.4 within 24 hours and removed the "Add to Existing" feature. | Visit malicious page while logged in to the extension | https://www.techtarget.com/searchsecurity/answer/The-Keeper-browser-extension-flaw-How-can-users-stay-secure |
| 12 | Keeper Desktop / KeeperFill | 2023 | CVE-2023-36266 (disputed) [V] | Secrets in process memory | Master password recoverable from process memory (PoC targeted the desktop app). Vendor disputes; NVD lists fix 17.2. | Local attacker reads memory | https://nvd.nist.gov/vuln/detail/CVE-2023-36266 |
| 13 | Dashlane extension | 2016 | no CVE [V] | Extension vulnerability (details not published) | Ormandy reported a vulnerability in Dashlane's browser extensions; Dashlane shipped a fix in September 2016. Technical class not disclosed. | Visit malicious page (presumed) | https://www.dashlane.com/blog/dashlane-update-1 |
| 14 | Bitwarden, Dashlane, Safari | 2022–23 | GHSA-mhhf-w9xw-pp9x (no CVE) [V] | Autofill into sandboxed / origin-less documents | Google Security Research: the managers filled saved credentials into pages served with a CSP `sandbox` header or inside sandboxed iframes, i.e. attacker-controlled content with a `null` origin hosted on the trusted domain. Bitwarden fixed it on 2022-12-14 and Dashlane on 2022-12-02. LastPass, 1Password, Chrome and Edge were not affected. | User-uploaded/sandboxed content served on a trusted domain | https://github.com/google/security-research/security/advisories/GHSA-mhhf-w9xw-pp9x |
| 15 | Bitwarden extension | 2018 | Cure53 BWN-01-001 [V] | Iframe origin not checked | Audit finding: autofill checked only the top-level page's domain, not the frame that contains the form. | Cross-origin iframe on a trusted page | https://pentestreports.com/reports%2FCure53/pentest-report_bitwarden.pdf |
| 16 | Bitwarden extension | 2023 | CVE-2023-27974 (disputed); CVE-2018-25081 (disputed/withdrawn) [V] | Autofill into cross-origin iframe + autofill on page load | Flashpoint: with "auto-fill on page load", Bitwarden filled the top-level site's credentials into an embedded cross-origin iframe. Bitwarden then added a warning and confirmation before manual fills into untrusted iframes. | Page-load autofill enabled (non-default) and a malicious iframe on a trusted site | https://flashpoint.io/blog/bitwarden-password-pilfering/ ; https://nvd.nist.gov/vuln/detail/CVE-2023-27974 |
| 17 | Bitwarden extension | 2023 | no CVE [V] | Over-broad matching (base domain → subdomains) | Default "Base domain" matching filled credentials on any subdomain, so hosting services that give users subdomains became exfiltration points. Bitwarden blocked autofill on the reported host. | Attacker controls a subdomain of a trusted domain | https://flashpoint.io/blog/bitwarden-password-pilfering/ |
| 18 | Bitwarden Desktop (Windows) | 2023 | CVE-2023-27706 [V] | Desktop-side key storage for browser/biometric unlock | Biometric unlock keys were stored in Windows Credential Manager, readable by any unprivileged process of the same user. Fixed in 2023.4.0. | Local malware as the same user | https://nvd.nist.gov/vuln/detail/CVE-2023-27706 |
| 19 | Bitwarden (cloud) | 2023 | no CVE [V] | KDF design: server-side iterations useless; server-controlled KDF params | Palant: only client-side PBKDF2 iterations protect a stolen vault (100k at the time, below OWASP guidance). A malicious server can tell clients to use only 5,000 iterations. Bitwarden raised the new-account default to 350,000 and later added Argon2id. | Server or DB compromise | https://palant.info/2023/01/23/bitwarden-design-flaw-server-side-iterations/ |
| 20 | Bitwarden extension ↔ desktop | 2023–24 | no CVE [U] | Native-messaging biometric bridge hardening | Bitwarden staff said behaviour changes to browser biometric unlock via the desktop app were made "to correct a vulnerability". No advisory found. | Unknown | https://community.bitwarden.com/t/unlock-this-user-in-the-desktop-application-and-try-again/68459 |
| 21 | 1Password 7 for Mac, Safari extension | 2021 | CVE-2021-41795 [V] | Extension ↔ app authorization bypass | A malicious web page could talk to the Safari app extension and read a subset of the vault items fillable on that page, with no user interaction while 1Password was unlocked. Fixed in 7.8.7. | Victim visits a page with JS targeting the extension | https://support.1password.com/kb/202109 |
| 22 | 1Password 7 for Mac | 2022 | CVE-2022-29868 [V] | IPC peer-validation bypass | A logic bug let local malware bypass 1Password's validation of other processes it talks to and exfiltrate vault items. Fixed in 7.9.3. | Local malware; app unlocked | https://support.1password.com/kb/202204/ |
| 23 | 1Password apps/integrations | 2022 | CVE-2022-32550 [V] | Sync protocol: server authentication | A non-standard SRP deviation meant that if TLS were broken (e.g. a rogue trusted CA), a malicious server could convince clients it was 1Password.com. | MITM with a certificate the device trusts | https://support.1password.com/kb/202206/ |
| 24 | 1Password 8 for Mac | 2024 | CVE-2024-42219 [V] | **Native messaging host / browser process impersonation** | "Browser Support getppid bypass": the desktop app checked the parent PID to verify that the caller was a real browser. A local process could impersonate the browser over XPC and obtain secrets. Fixed in 8.10.36. | Local malware as the same user | https://support.1password.com/kb/202408a/ |
| 25 | 1Password 8 for Mac | 2024 | CVE-2024-42218 [V] | Downgrade to older signed build | Loading an older 1Password version let an attacker reach Keychain-held secrets (biometric enforcement). Fixed in 8.10.38. | Local attacker | https://support.1password.com/kb/202408/ |
| 26 | 11 extensions: 1Password, Bitwarden, Dashlane, Enpass, iCloud Passwords, Keeper, LastPass, LogMeOnce, NordPass, Proton Pass, RoboForm (+ KeePassXC-Browser in later updates) | 2025 | CERT/CC VU#516608 (no CVE) [V] | **DOM-based extension clickjacking** | Marek Tóth (DEF CON 33): the page makes the extension's injected autofill UI invisible (opacity 0 on the extension element or on `<html>/<body>`, overlays with `pointer-events:none`, Popover API top layer) under a fake cookie banner or captcha. One click fills credentials, TOTP, card data, personal data or a passkey assertion into attacker-readable fields. Subdomain matching widens it (XSS/takeover on any subdomain). Fixed in: Bitwarden 2025.8.2, Dashlane 6.2531.1, Enpass 6.11.6, iCloud 3.1.30, Keeper 17.2.0, LogMeOnce 7.12.7, NordPass 5.13.24, Proton Pass 1.31.6, RoboForm 9.7.6, KeePassXC-Browser 1.9.11. 1Password and LastPass were still listed vulnerable as of 2026-01-14. | Attacker JS on the target domain or a subdomain (XSS, takeover, user-uploaded HTML/SVG) + one click | https://marektoth.com/blog/dom-based-extension-clickjacking/ ; https://kb.cert.org/vuls/id/516608 |
| 27 | 1Password extension | 2025 | no CVE [V] | Clickjacking mitigation (vendor response to #26) | 1Password added an optional "Ask before filling" confirmation for sensitive fills in 8.11.7.2. It states that it never fills into cross-origin iframes and fills only on saved domains. | — | https://support.1password.com/kb/202508 |
| 28 | Proton Pass extension | 2023 | Cure53 finding [V] | Over-broad `externally_connectable` | Cure53 audit: the manifest allowed wildcard domains to message the extension directly. | Attacker content on a matching domain | https://cure53.de/pentest-report_proton-pass.pdf |
| 29 | Proton Pass extension | 2026 | Recurity Labs audit finding [P] | Subdomain autofill (no strict host matching) | Saved logins were offered on related subdomains. | Attacker controls or injects into a subdomain | https://cyberinsider.com/proton-pass-rated-well-above-par-in-independent-security-audit/ |
| 30 | KeePassXC-Browser ≤1.9.9.2 | 2025 | CVE-2025-65203 [V] | Autofill into sandboxed (null-origin) documents | Filled or offered credentials inside CSP-sandboxed documents and sandboxed iframes, where attacker script can read the fields (same class as #14). Fixed in 1.9.9.3. | Sandboxed attacker content on a trusted origin | https://nvd.nist.gov/vuln/detail/CVE-2025-65203 |
| 31 | KeePassXC 2.3.0–2.7.x | 2026 | CVE-2026-118673 [V] | **Native messaging crypto: out-of-bounds write** | Out-of-bounds writes when encrypting and decrypting native-messaging messages. An associated client on the per-user IPC endpoint could trigger it with an oversized response. Fixed in 2.8.0. | Client with an existing association, DB unlocked | https://github.com/keepassxreboot/keepassxc/releases/tag/2.8.0 |
| 32 | KeePassXC (browser integration) | 2026 | CVE pending [V] | Untrusted data injection from extension into vault | Entry-reference injection (`{REF:...}`) when the browser extension created or updated entries. A web-influenced value could reference and leak other entries' fields. Fixed in 2.8.0. | Extension saves attacker-influenced data | https://github.com/keepassxreboot/keepassxc/releases/tag/2.8.0 |
| 33 | KeePassRPC (Kee/KeeFox) | 2020 | CVE-2020-16272 [V] | Local WebSocket bridge: broken SRP auth | The SRP-6a server did not validate client `A` (A=0), so any WebSocket client could authenticate and read or modify the open KeePass DB. Fixed in 1.12.0. | Reach the localhost WebSocket | https://nvd.nist.gov/vuln/detail/CVE-2020-16272 ; https://forum.kee.pm/t/a-critical-security-update-for-keepassrpc-is-available/3040 |
| 34 | KeePassRPC (Kee/KeeFox) | 2020 | CVE-2020-16271 [V] | Local WebSocket bridge: weak randomness | The SRP-6a implementation used insufficiently random numbers, allowing auth bypass over the WebSocket. CVSS 9.1. | Reach the localhost WebSocket | https://nvd.nist.gov/vuln/detail/CVE-2020-16271 |
| 35 | KeePassHttp + chromeIPass/PassIFox | ≤2017 (design) | no CVE [V] | Unauthenticated localhost HTTP + plaintext key exchange | KeePassHttp listened on `http://localhost:19455`. On pairing, the AES key was sent unencrypted. Any local observer or process could capture it and then query credentials. This is why KeePassXC replaced it with native messaging and NaCl box. | Local process or traffic observer during pairing | https://alan-null.github.io/chromeIPass/security ; https://github.com/pfn/keepasshttp/ |
| 36 | Trend Micro Password Manager | 2016 | CVE-2016-3987 [V] | **Unauthenticated local HTTP API → RCE + password theft** | A Node.js HTTP server on localhost (e.g. port 49155) exposed about 70 APIs with no origin checks. Any website could call `api/openUrlInDefaultBrowser`/`api/showSB` to execute commands, and could read passwords. | Visit malicious page | https://nvd.nist.gov/vuln/detail/CVE-2016-3987 ; https://www.securityweek.com/google-researcher-finds-rce-flaws-trend-micro-product/ |
| 37 | Avira Password Manager extension | 2022 | CVE-2022-28795 [V] | Autofill without user intent into attacker page | A crafted page could trigger the extension to auto-fill a password field and read it with script. Fixed in 2.18.5. | Visit malicious page | https://nvd.nist.gov/vuln/detail/CVE-2022-28795 |
| 38 | Avira Password Manager (Firefox) | 2026 | CVE-2026-12068 [V] | Fill into cross-origin iframe (wrong field selection) | Incorrect autofill field selection let a cross-origin iframe (e.g. an ad frame) receive credentials filled for the parent page. No fix planned at publication. | Malicious cross-origin iframe on visited page | https://nvd.nist.gov/vuln/detail/CVE-2026-12068 |
| 39 | Passbolt extension | 2019 | no CVE (CVSS 6.2) [V] | URL matching flaw (two domains in URL) | A URL containing two valid domain names made Passbolt suggest credentials for the wrong domain. Fix: exact subdomain matching when one is stored. Fixed in 2.11.2. | Phishing URL + user picks the suggestion | https://www.passbolt.com/incidents/autofill-suggestions |
| 40 | Any extension (demo: 1Password) | 2025 | no CVE [P] | Malicious extension impersonation ("polymorphic extensions") | SquareX: a benign-looking extension enumerates installed extensions, then swaps its icon and UI to mimic the password manager and phishes the master password. No vendor patch is possible. | User installs a malicious extension | https://sqrx.com/polymorphic-extensions |
| 41 | Chrome, Safari, Opera autofill; LastPass | 2017 | no CVE [P] | Fill into hidden fields | Viljami Kuosmanen: a page shows name and email inputs while hidden fields also receive address, phone and card data from profile autofill. Firefox was not affected (per-field fill). | User accepts autofill on attacker page | https://www.theregister.com/2017/01/10/autocomplete_a_novel_phishing_hole_for_chrome_safari_crims/ |
| 42 | Browser built-in managers (Firefox, Chrome, Edge, IE, Safari) | 2017 | no CVE [V] | Third-party script harvests autofilled credentials via invisible forms | Princeton CITP: tracking scripts (AdThink, OnAudience) on about 1,100 of the top 1M sites injected invisible login forms. Browsers auto-filled the saved email and password, and scripts exfiltrated a hash of the email. | Third-party script in a first-party page where the user saved credentials | https://blog.citp.princeton.edu/2017/12/27/no-boundaries-for-user-identities-web-trackers-exploit-browser-login-managers/ |
| 43 | Android managers (1Password, LastPass, Enpass, Keeper, Keepass2Android, …) | 2023 | "AutoSpill" (no CVE) [P] | Autofill target confusion (WebView vs host app) | Credentials requested for a WebView page were filled into the host app's native fields. Mobile, but the same lesson: fill only the field the user chose, in the context that owns the origin. | Malicious app hosting a WebView | https://www.bleepingcomputer.com/news/security/autospill-attack-steals-credentials-from-android-password-managers/ |
| 44 | 1Password, LastPass, others (desktop) | 2026 | NDSS 2026 "Vault Raider" [P] | UI-level attacks on desktop autofill/approval dialogs | UIC researchers triggered legitimate password-manager desktop functions stealthily via window manipulation on macOS and Windows. Some vendors fixed issues; one paid a bounty. | Local unprivileged app | https://www.ndss-symposium.org/ndss-paper/vault-raider-stealthy-ui-based-attacks-against-password-managers-in-desktop-environments/ |
| 45 | KeePass 2.x | 2023 | CVE-2023-24055 (disputed) [V] | Writable config → silent export trigger | An attacker with write access to the KeePass config could add a trigger that exports the DB in cleartext when it is opened. | Local write to user config | https://nvd.nist.gov/vuln/detail/CVE-2023-24055 |
| 46 | Dashlane extension | 2025 | no CVE found [P] | Undisclosed extension flaw | Reported by an external researcher on 2025-07-28 and fixed on 2025-08-01 in 6.2531.1, the same version that fixed #26 for Dashlane. No exploitation known. Vendor page was 403 to the fetcher. | — | https://support.dashlane.com/hc/articles/28598967624722 |
| 47 | Dashlane extension | 2025 | no CVE found [P] | Cryptographic downgrade | A "cryptography downgrade" issue in extension ≤6.2543 was fixed on 2025-11-05 in 6.2544.1. Vendor page was 403, so details are not verified. | Unknown | https://support.dashlane.com/hc/articles/33346483084050 |
| 48 | RoboForm | 2025 | CVE-2025-26700 [P] | Local authentication bypass | CWE-288 local auth bypass in RoboForm Password Manager. Not an extension bug; listed for the desktop-bridge threat model. | Local attacker | https://www.tenable.com/cve/CVE-2025-26700 |

Products in scope with **no separate public extension CVE found** (besides #26): NordPass, RoboForm (extension), Enpass, iCloud Passwords, LogMeOnce. NordPass and RoboForm appear only via Tóth's research. "1Password X / Brave" issues: no public vulnerability found linking 1Password to Brave specifically **[U]**. CVE-2017-12865 is **not** a Keeper CVE; it was searched and not attributable, so it is excluded.

Research and guidance rows (not product bugs):

| Ref | Year | Finding | URL |
|---|---|---|---|
| R1 | 2014 | Silver et al.: sweep attacks, iframe fill, HTTP→HTTPS fill, autofill-without-interaction (background) | https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/silver |
| R2 | 2014 | Stock & Johns: XSS reads autofilled passwords; nonce-fill defence | https://notify.cispa.uni-saarland.de/papers/stock2014protecting.pdf |
| R3 | 2018 | Palant, *Password managers, please make sure autofill is secure*: use browser URL parser, PSL not "last two labels", treat IPs separately, only www equivalence, require `isTrusted` user action, fill only top-level/first-party frames, don't ask master password in page frames | https://palant.info/2018/08/29/password-managers-please-make-sure-autofill-is-secure |
| R4 | 2020 | Oesch & Ruoti (USENIX Sec 2020): 13 managers; remaining issues with iframe filling, fill without interaction, form/action verification, clickjacking | https://www.usenix.org/conference/usenixsecurity20/presentation/oesch |
| R5 | 2025 | Tóth DOM clickjacking and mitigations (closed shadow root, MutationObserver, `elementsFromPoint`, top-layer checks, separate popup window) | https://marektoth.com/blog/dom-based-extension-clickjacking/ |

---

## 2. Grouped by vulnerability class

**A. Origin determination / URL matching flaws** (#1, #17, #29, #39, #26 subdomain aspect, R3)
Hand-rolled URL parsing (LastPass regex), base-domain or subdomain matching by default (Bitwarden, Proton Pass, all 11 in Tóth's study), and "two domains in URL" confusion (Passbolt). Root cause: the extension's notion of "which site is this" differs from the browser's, or the matching is broader than the user expects.

**B. Frame / context confusion** (#14, #15, #16, #30, #38, #43)
Filling into cross-origin iframes (Bitwarden, Avira/Firefox) or into sandboxed null-origin documents on a trusted host (Google GHSA: Bitwarden/Dashlane/Safari; KeePassXC-Browser CVE-2025-65203). The top-level URL matches but the frame receiving the secret is not that origin.

**C. Autofill without a trusted user gesture / into hidden fields** (#16 page-load autofill, #37, #41, #42, R1, R2)
Page-load autofill and filling invisible fields enable sweep attacks, tracker harvesting and XSS harvesting.

**D. Clickjacking of extension UI** (#6, #10, #11, #26, #27)
In-page UI injected into the page DOM can be hidden, overlaid or moved by the page. Popup-window tricks and fake input (Keeper 2016/2017). DOM-based extension clickjacking (2025) hit essentially every major extension, including TOTP, cards and passkeys.

**E. Page → extension privilege confusion / message channel abuse** (#2, #3, #5, #21, #28)
Content scripts that relay page messages to privileged code (LastPass websiteConnector), `externally_connectable` wildcards (Proton Pass), and app-extension auth bypass (1Password Safari).

**F. Extension ↔ native/desktop bridge** (#4, #24, #22, #31, #32, #33, #34, #35, #36, #20, #18)
- Local listening servers: Trend Micro (HTTP, RCE), KeePassHttp (HTTP, plaintext key exchange), KeePassRPC (WebSocket with broken SRP).
- Weak caller authentication: 1Password getppid check (CVE-2024-42219), process validation bypass (CVE-2022-29868).
- Memory-safety in bridge crypto (KeePassXC CVE-2026-118673).
- Untrusted extension data injected into the vault (KeePassXC entry reference injection).
- Over-powerful bridge commands (LastPass `openattach` → RCE).
- Bridge secrets stored insecurely on the desktop (Bitwarden CVE-2023-27706).

**G. Cloud sync / KDF / server trust** (#7, #8, #9, #19, #23, #47)
Unencrypted URL metadata, legacy low iteration counts never upgraded, server-controlled KDF parameters, non-standard PAKE weakening server authentication, crypto downgrade. LockAlperen is offline, but these apply to any future sync or export format.

**H. Local attacker / desktop hardening** (#12, #25, #44, #45, #48)
Memory scraping, downgrade to an old signed build, UI-automation attacks on approval dialogs, config-file trigger injection, local auth bypass.

**I. Malicious-extension impersonation** (#40)
Polymorphic extensions phish the master password by mimicking the password manager's popup.

---

## 3. Design requirements for the LockAlperen extension

MUST = release blocker. SHOULD = strong default; deviate only with a documented reason. Each rule cites the failures it prevents.

### 3.1 Origin determination and matching
1. **MUST** derive the requesting origin in the background/service worker from browser-supplied data (`sender.origin` / `sender.url` / `sender.frameId` via `webNavigation.getFrame`). Never trust a URL or origin sent in a content-script message body. *(#1, #3, #39)*
2. **MUST** parse URLs only with the WHATWG `URL` parser (browser `URL` in the extension, the `url` crate in Rust). No regexes or string splitting. Reject URLs with userinfo (`user:pass@`), and refuse to fill on `data:`, `blob:`, `file:`, `about:`, `javascript:`, `chrome-extension:` and other non-http(s) schemes. *(#1, R3)*
3. **MUST** match by default on the **exact origin**: scheme + host + port.
   - https-saved credentials never fill on http.
   - A different port means a different origin.
   - IP addresses match exactly and are never PSL-reduced.
   - IDN hosts are compared in punycode, and the UI shows a warning on mixed-script or confusable hosts.
   *(#17, #26, #29, #39, R1, R3)*
4. **SHOULD** offer broader matching ("same registrable domain", computed with an embedded, versioned Public Suffix List, never "last two labels") only as an **explicit per-entry opt-in**. Even then, show the exact host in the fill UI. `www.` ↔ apex may be treated as equivalent by default. *(R3, #17, #29)*
5. **MUST** perform matching in the desktop app (Rust) as well. The desktop independently recomputes the match from the origin the extension reports and returns only entries that match that origin. It never returns "all entries", and there is no search-everything command over the bridge. *(#3, #21)*

### 3.2 Frames and document context
6. **MUST** fill only into the top-level frame, or into a same-origin child frame whose origin equals both the top-level origin and the entry's origin. Never fill into cross-origin iframes; don't offer them at all. *(#14, #15, #16, #38, 1Password policy #27)*
7. **MUST** refuse to fill into documents with an opaque/`null` origin: CSP `sandbox` responses, sandboxed iframes, `srcdoc`/`about:blank` frames that don't inherit a matching origin. Check `self.origin`/`location.origin === "null"` in the content script, and also check frame origin from the background. *(#14, #30)*
8. **SHOULD** warn when a form's `action` (or the destination of a JS submit, where detectable) is a different origin from the page. *(R4)*

### 3.3 User intent, visibility, what gets filled
9. **MUST NOT** auto-fill on page load. Ever. There is no setting for it. *(#16, #37, #42, R1)*
10. **MUST** fill only after a trusted user gesture delivered **outside the page's DOM**. Primary paths:
    - toolbar popup (`action`);
    - keyboard shortcut (`commands`);
    - context menu.

    The page cannot overlay, restyle or hide these. *(#26, #10/#11, R5)*
11. If an in-page inline menu or icon is added later, it **MUST**:
    - render inside a **closed** shadow root or a separate extension-origin iframe;
    - require `event.isTrusted`;
    - run a MutationObserver on its host and on `<html>/<body>` for opacity, visibility, transform, clip and filter changes;
    - check `document.elementsFromPoint()` at the click point to confirm that the topmost element is ours;
    - abort if any top-layer popover or dialog exists;
    - impose a short minimum display time before accepting clicks.

    Even with all of this, it **SHOULD** only open the real choice UI (popup or desktop), never fill directly from an in-page click. *(#26, R5)*
12. **MUST** fill only fields that are visible, enabled, non-zero size, in the viewport, not `opacity:0`/`visibility:hidden`, and not `aria-hidden`. Fill only the username and password of the single form the user targeted. Never fill other forms on the page. *(#41, #42, R1)*
13. **MUST** require a **separate, explicit action** for TOTP codes, card data and identities. Never piggy-back them on a login fill. TOTP is copied or filled only when the user asks for that specific item. *(#26 TOTP/card leakage)*
14. **SHOULD** show the exact origin being filled into in the popup and in any desktop confirmation. For a first fill of an entry on an origin, the desktop app **SHOULD** ask for confirmation, with a "remember for this origin" option (KeePassXC-style access confirm).
15. **SHOULD** offer the Stock & Johns mitigation as an advanced option: fill a random placeholder and substitute the real password only on a trusted submit to the matching origin. *(R2)*

### 3.4 Extension surface hardening (Manifest V3)
16. **MUST NOT** declare `externally_connectable`, and **MUST NOT** register `runtime.onMessageExternal`. No web page or other extension can message us. *(#28, #21)*
17. **MUST** treat every content-script message as untrusted. Content scripts send only:
    - "user requested fill here", with field descriptors;
    - "page has login form".

    The background validates `sender.id === chrome.runtime.id`, `sender.tab`, `sender.frameId` and origin. The content script never relays page-originated `postMessage` data to privileged code. *(#3, #2, #5)*
18. **MUST** expose a minimal command set over all channels. The extension cannot open files, launch programs, export the vault, change settings, or read entries other than origin-matched credentials. *(#4 `openattach` RCE, #36)*
19. **MUST** use the default MV3 CSP or stricter: no `eval`, no remote code, no `unsafe-inline`. Use no `innerHTML` with vault or page data in extension pages (use `textContent`/a framework with escaping). Keep `web_accessible_resources` empty or minimal with `use_dynamic_url: true`, so extension pages cannot be framed or fingerprinted. *(XSS-in-extension classes; #40 fingerprinting by "web resource hitting")*
20. **MUST NOT** store vault secrets in `chrome.storage`/`localStorage`/IndexedDB. Secrets live only in memory for the duration of a fill and are zeroed or dropped afterwards. Never cache "last filled credentials" across tabs or origins. *(#6)*
21. **SHOULD** request the fewest permissions possible: `activeTab`, `scripting` and `nativeMessaging`, with host access granted on click where feasible. Static content scripts on `<all_urls>` only if needed for form detection.

### 3.5 Native messaging bridge (extension ↔ desktop)
22. **MUST NOT** open any listening TCP/UDP/HTTP/WebSocket port, on localhost or elsewhere. The only path is browser native messaging (stdio) to a small host binary. That host relays to the running Tauri app over:
    - a Unix domain socket in `$XDG_RUNTIME_DIR` (directory 0700, socket 0600) on Linux;
    - a named pipe with a DACL restricted to the current user SID and `PIPE_REJECT_REMOTE_CLIENTS` on Windows.

    *(#33, #34, #35, #36)*
23. **MUST** list exactly our published extension IDs in the native-host manifest (`allowed_origins` for Chromium, `allowed_extensions` for Firefox), with no wildcards. Install the manifest in per-user locations the installer owns, and document the system-wide locations. The desktop app **SHOULD** detect and warn about foreign or modified host manifests pointing at a different binary (native-host hijack).
24. **MUST NOT** rely on process identity checks for authentication: parent PID, executable path, or "is the caller a browser". These are defence-in-depth only (`SO_PEERCRED`/`GetNamedPipeClientProcessId`, same-user check). **Authentication MUST be cryptographic.** *(#24 getppid bypass, #22)*
25. **MUST** pair the extension and the desktop with an authenticated key exchange:
    - X25519 ephemeral + static keys (Noise `XX`/`IK`, or NaCl box as KeePassXC does);
    - the user verifies a short authentication string or fingerprint shown in **both** the desktop app and the extension popup, and approves in the desktop app;
    - no key is ever transmitted in plaintext;
    - every pairing has a name, a creation date and a last-used date, and can be revoked from the desktop UI.

    *(#35 KeePassHttp plaintext key, #33/#34 broken SRP)*
26. **MUST** protect every post-pairing message with an AEAD (XChaCha20-Poly1305) under session keys. Use a monotonically increasing counter or nonce with replay rejection, a protocol version in the associated data, and refusal to negotiate older versions (no downgrade). Use audited crates (RustCrypto/libsodium bindings) and no custom crypto or PAKE. *(#23, #33, #34, #47, #25)*
27. **MUST** enforce strict length limits on bridge messages, and parse with bounded, typed deserialization (serde with size caps) on both host and app. Never allocate based on unvalidated lengths. Rust safety is the baseline; `unsafe` is forbidden in bridge code. Fuzz the decoder. *(#31)*
28. **MUST** treat all data arriving from the extension (new-entry title, username, URL, notes) as untrusted. Store it literally: escape or disable placeholder and reference syntax so it can never resolve to another entry's fields, and never interpret it as commands or triggers. *(#32, #45)*
29. **MUST** have the bridge return nothing while the vault is locked. Unlocking happens **only in the desktop app** (OS biometrics or master password). **The extension MUST NOT ever ask for the master password**, so a polymorphic or impersonating extension's "enter your master password" prompt is always anomalous, and the UI should say so. *(#40, R3 "don't ask for master password in page frames")*
30. **SHOULD** rate-limit bridge requests and log them in a local audit view: origin, entry, time, pairing. **SHOULD** require desktop confirmation for any write or save from the extension.
31. **MUST** keep any key material for "unlock via browser" or biometric bridging in OS-protected storage bound to user presence: DPAPI with Windows Hello key-protected credentials, or Secret Service/kernel keyring on Linux with a user-presence check. Never use plain Credential Manager or a readable file. *(#18)*

### 3.6 Desktop-side confirmation UI
32. **SHOULD** make approval dialogs (pairing, first fill, save) resistant to UI-redress and focus attacks:
    - always-on-top;
    - ignore clicks or Enter for about 500 ms after appearing;
    - require deliberate action, not a default-focused button;
    - show the origin and the pairing name prominently.

    *(#44, #11)*
33. **MUST** keep config, native-host manifest and pairing-key files writable only by the user, and treat config as data, never executable triggers. **SHOULD** verify integrity of pairing state with a MAC under a vault-derived key. *(#45)*
34. **SHOULD** use the auto-updater's signature checks with a minimum-version floor, so an older vulnerable signed build cannot be substituted. *(#25)*

### 3.7 If sync, backup or export is ever added
35. **MUST** encrypt all vault metadata, including URLs, titles, icons and timestamps where feasible. Nothing about which sites a user has should be readable without the key. *(#7)*
36. **MUST** derive keys client-side with Argon2id at strong parameters, store the parameters inside the authenticated vault header, and enforce a client-side minimum. Never accept weaker KDF parameters from a server or file without a user-visible warning. Upgrade legacy parameters on the next unlock. *(#8, #19)*
37. **MUST** authenticate any sync server independently of TLS where possible: pinned keys, or E2E-authenticated blobs whose server identity is irrelevant. Use standard protocols only. *(#23)*

### 3.8 Process
38. **SHOULD** commission an external audit of the extension and bridge before 1.0. Re-test against Tóth's PoCs (R5), the Google sandbox PoC (#14) and Flashpoint's iframe PoC (#16) on every release. Publish a security.txt / disclosure policy.
