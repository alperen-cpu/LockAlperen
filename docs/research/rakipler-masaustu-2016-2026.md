# Local / desktop password manager vulnerabilities, 2016–2026: research notes for LockAlperen

Scope: local or desktop vault products and their desktop clients (KeePass 2.x, KeePassXC, KeePassX, KeeWeb, KeePassDX where the KDBX format is involved, Bitwarden desktop, 1Password 7/8 desktop, Enpass, Password Safe, Dashlane/LastPass desktop components).
Compiled 2026-11-24. CVE descriptions were checked against the MITRE CVE API (cveawg.mitre.org) or NVD where noted. Items marked "research" have no CVE. Items marked "disputed" are contested by the vendor. A few pre-2016 items appear at the end for context only.

Legend for preconditions: **LOCAL-USER** = attacker code runs as the same OS user; **LOCAL-ADMIN** = admin/root; **FS-WRITE** = can write to a user-writable file or directory; **DUMP** = can read a memory dump, swap, hiberfil or crash dump; **NET-MITM** = on-path network attacker; **MALICIOUS-FILE** = victim opens or imports a crafted file; **MALICIOUS-SERVER** = victim points the app at an attacker server; **SOCIAL** = victim installs a fake build.

## 1. Master table

| # | Product | Year | ID | Vulnerability class | Short description | Attack precondition | Source URL |
|---|---|---|---|---|---|---|---|
| 1 | KeePass 2.x | 2023 | CVE-2023-32784 | Memory residue | The custom SecureTextBox leaves a residual string for each typed character. The master password, except the first character, can be recovered from a process dump, pagefile, hiberfil or RAM, even after locking or exit. Fixed in 2.54. | DUMP | https://nvd.nist.gov/vuln/detail/CVE-2023-32784 ; PoC https://github.com/vdohney/keepass-password-dumper |
| 2 | KeePass 2.x | 2023 | CVE-2023-24055 (disputed) | Export/config tampering | Anyone with write access to KeePass.config.xml can add a trigger that silently exports the database in cleartext after the next unlock. The vendor says this is out of the threat model; the mitigation is an enforced config. | LOCAL-USER + FS-WRITE | https://nvd.nist.gov/vuln/detail/CVE-2023-24055 ; https://www.bleepingcomputer.com/news/security/keepass-disputes-vulnerability-allowing-stealthy-password-theft/ |
| 3 | KeePass 2.x | 2016 | CVE-2016-5119 | Update / supply chain | The update check fetched version info over plain HTTP with no signature, so a MITM could spoof it and point the user to a malicious "update". Fixed in 2.34: the version file is now fetched over HTTPS and RSA-4096/SHA-512 signed. | NET-MITM | https://nvd.nist.gov/vuln/detail/CVE-2016-5119 ; https://keepass.info/help/kb/sec_issues.html |
| 4 | KeePass 2.x (Fedora pkg) | 2022 | CVE-2022-0725 (disputed) | Clipboard / logging leak | Clipboard contents (passwords) appeared in the systemd journal when the clipboard was cleared on Linux. Upstream blames an external component and changed the clipboard method in 2.54. | LOCAL-USER (read journal) | https://nvd.nist.gov/vuln/detail/CVE-2022-0725 ; https://bugzilla.redhat.com/show_bug.cgi?id=2052696 |
| 5 | KeePass 2.x | 2020 | CVE-2019-20184 (disputed) | Export / formula injection | CSV export does not neutralise `=`, `+`, `-`, `@` prefixes, so the export becomes a formula-injection payload in Excel or Calc. The vendor will not fix it. | MALICIOUS-ENTRY (attacker-controlled title, e.g. via shared DB or import) + victim opens CSV | https://nvd.nist.gov/vuln/detail/CVE-2019-20184 |
| 6 | KeePass 2.x | 2026 | CVE-2026-86776 (disputed) | File-format parsing (DoS) | KeePass 2.35–2.61.1 does not validate KDBX header-field sizes before allocating memory, so a crafted header can force gigabyte allocations and terminate the app. | MALICIOUS-FILE | https://cveawg.mitre.org/api/cve/CVE-2026-86776 ; https://keepass.info/help/kb/sec_issues.html |
| 7 | KeePass 2.x | 2016 | research (KeeThief, Harmj0y/GhostPack) | Memory residue / DPAPI key theft | Reads the composite key from the CLR heap of a running KeePass and decrypts the DPAPI-protected "Windows user account" key file. Also backdoors the trigger system. | LOCAL-USER | https://github.com/GhostPack/KeeThief |
| 8 | KeePass 2.x | 2022 | research (KeeFarceReborn) | Malicious plugin / injection | An injected DLL uses KeePass's own export API to dump the open database in cleartext. | LOCAL-USER | https://github.com/d3lb3/KeeFarceReborn |
| 9 | KeePass 2.x | 2023 | research (Quarkslab) | DLL/plugin hijack | Compiled PLGX plugins are cached as DLLs in user-writable `%LocalAppData%\KeePass\PluginCache`, so overwriting the cached DLL gives code execution inside KeePass even when it is installed in Program Files. | LOCAL-USER + FS-WRITE | https://blog.quarkslab.com/post-exploitation-abusing-the-keepass-plugin-cache.html |
| 10 | KeePass 2.x | 2025 | research (WithSecure "KeeLoader") | Update / supply chain (trojanized build) | Malvertising led to typosquatted sites serving a validly signed, trojanized KeePass build. It exported the DB in cleartext and dropped Cobalt Strike, ending in ESXi ransomware. | SOCIAL | https://www.withsecure.com/en/resources-hub/w-labs/keepass-trojanised-in-advanced-malware-campaign/ |
| 11 | KeePass 2.x | 2019 | research (ISE "Under the Hood of Secrets Management") | Memory residue | Entries stay in cleartext in process memory after use and are not scrubbed on lock. The master password was not recoverable in 2019 (later disproven by #1). | DUMP / LOCAL-USER | https://ise.io/casestudies/password-manager-hacking/ |
| 12 | KeePass 2.x | n/a (documented) | research (KeePass sec_issues) | Auto-type window targeting | Auto-type picks the target window by title, which is spoofable, so a malicious window with a matching title receives the keystrokes. Treated as a design limitation. | LOCAL-USER | https://keepass.info/help/kb/sec_issues.html |
| 13 | KeePass 2.x / all | 2018–2019 | research (Win10 1809 clipboard history / cloud clipboard) | Clipboard | Windows clipboard history and cloud sync kept copied passwords after the app cleared the clipboard. KeePass 2.41 added the `ExcludeClipboardContentFromMonitorProcessing` / `CanIncludeInClipboardHistory=0` formats. 1Password users were told to disable clipboard history. | LOCAL-USER / cloud account | https://keepass.info/help/base/security.html ; https://community.bitwarden.com/t/dont-store-password-in-windows-10-clipboard-history-cloud-clipboard/3876 |
| 14 | KeePassRPC (KeePass plugin for Kee) | 2020 | CVE-2020-16271 | Crypto / IPC auth | Weak randomness in the SRP-6a implementation of the local WebSocket server let a remote party read and modify the DB. Fixed in 1.12.0. | Local WebSocket reachable (malicious web page / local process) | https://nvd.nist.gov/vuln/detail/CVE-2020-16271 |
| 15 | KeePassRPC | 2020 | CVE-2020-16272 | Crypto / IPC auth | Missing SRP parameter validation (A=0) gives an auth bypass on the WebSocket that exposes read/write access to the DB. | as above | https://nvd.nist.gov/vuln/detail/CVE-2020-16272 |
| 16 | KeePassXC | 2026 | CVE-2026-4158 / ZDI-26-215 / GHSA-4gr2-cr97-q9fx | DLL/library hijack (OpenSSL config search path) | On Windows before 2.7.12, KeePassXC loaded an OpenSSL config from an uncontrolled path, so a planted config loads an attacker engine/provider DLL, giving local privilege escalation. | LOCAL-USER (low priv) + user interaction | https://nvd.nist.gov/vuln/detail/CVE-2026-4158 ; https://zerodayinitiative.com/advisories/ZDI-26-215 |
| 17 | KeePassXC | 2026 | CVE-2026-69150 | File-format parsing (memory safety) | KDB (KeePass 1) legacy import kept stale Entry pointers, so a crafted KPX_CUSTOM_ICONS_4 metastream gave a heap use-after-free with a controlled write. Fixed in 2.8.0-beta1. | MALICIOUS-FILE (unlockable .kdb) | https://cveawg.mitre.org/api/cve/CVE-2026-69150 ; https://github.com/keepassxreboot/keepassxc/releases |
| 18 | KeePassXC | 2026 | CVE pending (2.8.0 notes) | File-format parsing | Integer overflow and out-of-bounds read in the legacy KDB importer (NATO CSC). | MALICIOUS-FILE | https://github.com/keepassxreboot/keepassxc/releases ; https://gbhackers.com/keepassxc-2-8-0-released/ |
| 19 | KeePassXC | 2026 | CVE-2026-118673 | IPC (browser native messaging) memory corruption | Browser responses were encrypted into a fixed 1 MiB vector, so a large authorised response caused an out-of-bounds write. Affects 2.3.0 to before 2.8.0. | Local client of the per-user IPC socket with a valid association | https://cveawg.mitre.org/api/cve/CVE-2026-118673 |
| 20 | KeePassXC | 2026 | CVE pending (2.8.0 notes) | IPC / entry-reference injection | The browser extension could inject `{REF:...}` entry references when creating or updating entries, which can pull other entries' secrets. | Paired browser / malicious page via extension | https://github.com/keepassxreboot/keepassxc/releases |
| 21 | KeePassXC | 2026 | CVE pending (2.8.0 notes) | IPC / local shared memory | On Windows, the predictable shared-memory mapping name used to hand SSH keys to Pageant allowed squatting or sniffing. Names are now randomised. | LOCAL-USER | https://github.com/keepassxreboot/keepassxc/releases |
| 22 | KeePassXC | 2026 | no CVE (2.8.0 notes) | Memory residue | Decrypted DB fragments remained in zlib's internal buffers. 2.8.0 clears them more thoroughly. | DUMP | https://github.com/keepassxreboot/keepassxc/releases |
| 23 | KeePassXC | 2026 | no CVE (2.7.12 notes) | Path traversal / attachment handling | Attachment file names were not sanitised before saving to disk (fixed in 2.7.12, #13114). | MALICIOUS-FILE (crafted attachment name) | https://github.com/keepassxreboot/keepassxc/releases |
| 24 | KeePassXC | 2025 | no CVE (2.7.11 notes) | Local privilege (installer) | The MSI could launch KeePassXC as SYSTEM at the end of install, exposing a SYSTEM GUI with file dialogs. Fixed in 2.7.11 (#12705). | Installer run elevated | https://github.com/keepassxreboot/keepassxc/releases |
| 25 | KeePassXC | 2024 | CVE-2024-33900 (disputed) | Memory residue | Cleartext credentials are recoverable from a memory dump of 2.7.7. | DUMP (same user) | https://nvd.nist.gov/vuln/detail/CVE-2024-33900 |
| 26 | KeePassXC | 2024 | CVE-2024-33901 (disputed) | Memory residue | Some stored entry passwords are recoverable from a memory dump of 2.7.7. | DUMP | https://nvd.nist.gov/vuln/detail/CVE-2024-33901 |
| 27 | KeePassXC | 2024 | no CVE (2.7.7 #10266); research USENIX Sec '24 (Fábrega et al.) | Crypto side channel (compression/dedup) | An attacker who can inject entries (via a KeeShare-synced DB) can use KDBX GZip compression and attachment deduplication as a size oracle to recover URLs, usernames and attachments byte by byte. KeePassXC added random padding and salted dedup. | Attacker controls a shared DB + observes ciphertext size | https://arxiv.org/abs/2408.07054 ; https://github.com/keepassxreboot/keepassxc/releases/tag/2.7.7 |
| 28 | KeePassXC | 2023 | CVE-2023-35866 (disputed) | Re-auth missing for sensitive settings | Master password and 2FA settings can be changed in an unlocked session without re-entering the password. | LOCAL-USER with unlocked session | https://nvd.nist.gov/vuln/detail/CVE-2023-35866 |
| 29 | KeePassXC-Browser | 2025 | CVE-2025-65203 / GHSA-86gj-qj6h-cwmx | Autofill origin confusion | Credentials were autofilled into CSP- or iframe-sandboxed documents, so attacker script in the sandbox can read the filled fields. | Malicious web page | https://nvd.nist.gov/vuln/detail/CVE-2025-65203 |
| 30 | KeePassXC (+ MacPass, Keeper, 1Password, LastPass) | 2026 | research (NDSS '26 "Vault Raider", Infantino et al.) | Auto-type / UI spoofing / synthetic input | A malicious app spoofs the window title or bundle display name, brute-forces the auto-type hotkey with synthetic key presses, and drives the selection popup to exfiltrate every credential. Windows lacks OS-level caller identity. | LOCAL-USER (no admin) | https://www.ndss-symposium.org/ndss-paper/vault-raider-stealthy-ui-based-attacks-against-password-managers-in-desktop-environments/ |
| 31 | KeePassDX (Android, KDBX parser) | 2018 | CVE-2018-1000835 | File-format parsing (XXE) | The KDBX XML parser resolved external entities, enabling file disclosure, SSRF, DoS and port scanning. | MALICIOUS-FILE | https://nvd.nist.gov/vuln/detail/CVE-2018-1000835 |
| 32 | KeeWeb | 2020 | research / Packet Storm VL-2237 (no CVE found) | HTML injection in notes (Electron) | HTML injection via the notes field in KeeWeb 1.14.0, web and Windows desktop. Kee Vault later fixed "social engineering" issues in shared KeeWeb UI code. Fix status unverified. | MALICIOUS-FILE / shared DB | https://packetstormsecurity.com/files/157595/VL-2237.txt ; https://forum.kee.pm/t/kee-vault-security-update-released/2961 |
| 33 | Bitwarden desktop (Win) | 2023 | CVE-2023-27706 / GHSA-fq2f-69mj-r56v | Local key storage / biometric unlock | The Windows Hello biometric key (equal to the vault key) was stored in Windows Credential Manager, where any same-user process could read it. Fixed in 2023.4.0. | LOCAL-USER | https://nvd.nist.gov/vuln/detail/CVE-2023-27706 |
| 34 | Bitwarden desktop | 2023 | CVE-2023-38840 / GHSA-vc8h-v53f-wpq5 | Memory residue | The master password stays in Bitwarden.exe memory after lock (PoC bw-dump). Affects ≤2023.7.0; fix in clients PR #5813. | DUMP / LOCAL-USER | https://nvd.nist.gov/vuln/detail/CVE-2023-38840 ; https://github.com/markuta/bw-dump |
| 35 | Bitwarden desktop | 2023 | Cure53 BWN-08-014 (Critical) | Remote content → RCE (Electron) | The desktop client iframed server-supplied hCaptcha content in the main window. A malicious self-hosted server could redirect the main window and get Node.js API access, i.e. RCE. | MALICIOUS-SERVER (user enters attacker URL) | https://bitwarden.com/assets/6m0rD5aBvmE7LtOGJrpYdP/199f548d2dd29fd120099cf0c64d5bd1/2023_Bitwarden_Electron_Desktop_App_Security_Assessment_Report.pdf |
| 36 | Bitwarden desktop | 2023 | Cure53 BWN-08-013 (Medium) | Insecure webview config | The main BrowserWindow ran with `nodeIntegration: true` and `contextIsolation: false`, so any XSS or redirect became RCE. | Any XSS / navigation | same as above |
| 37 | Bitwarden desktop | 2018 | Cure53 BWN-01-006 (Critical) | URI handling → RCE | A malicious login URI with a dangerous scheme, opened from the desktop app, gave code execution (classic Electron `shell.openExternal` issue). | MALICIOUS-ENTRY (shared/imported item) | https://pentestreports.com/reports%2FCure53/pentest-report_bitwarden.pdf |
| 38 | Bitwarden desktop / ext | 2023 | research (ambiso "Bitwarden PINs can be brute-forced") | Crypto / KDF (low-entropy unlock) | The PIN-unlock key is stored locally, wrapped with PBKDF2 over a 4-digit PIN, so it is brute-forceable offline in seconds and the 5-attempt limit is bypassed. Not a CVE; Bitwarden added a warning. | FS-READ of app data | https://ambiso.github.io/bitwarden-pin |
| 39 | Bitwarden (all clients) | 2023 | research / vendor change | Crypto / KDF iterations | After the LastPass breach, Bitwarden raised the default PBKDF2 iterations to 600k (2023.2.0), added Argon2id, and later enforced a 600k minimum on old accounts. | Offline attacker with vault blob | https://bitwarden.com/help/kdf-algorithms/ |
| 40 | Bitwarden (fake installer) | 2023 | research (Proofpoint ZenRAT) | Supply chain / fake installer | The lookalike domain bitwariden[.]com served a trojanized Bitwarden installer that dropped the ZenRAT infostealer. | SOCIAL | https://www.proofpoint.com/us/blog/threat-insight/zenrat-malware-brings-more-chaos-calm |
| 41 | Bitwarden CLI (npm) | 2026 | incident (no CVE) | Supply chain (CI/CD compromise) | `@bitwarden/cli@2026.4.0` was published with a credential-stealing preinstall after a GitHub Action in the CI pipeline was compromised. It was live for about 93 minutes. | Victim installs/updates during window | https://thehackernews.com/2026/04/bitwarden-cli-compromised-in-ongoing.html ; https://socket.dev/blog/bitwarden-cli-compromised |
| 42 | 1Password 8 (Mac) | 2024 | CVE-2024-42219 | IPC validation | Insufficient XPC IPC validation let local processes exfiltrate vault items. Fixed in 8.10.36. | LOCAL-USER | https://support.1password.com/kb/202408a/ |
| 43 | 1Password 8 (Mac) | 2024 | CVE-2024-42218 | Downgrade / code-identity | An attacker who installs an old 1Password build can access 1Password secrets in the macOS Keychain. Fixed in 8.10.38. | LOCAL-USER | https://support.1password.com/kb/202408/ |
| 44 | 1Password 7/8 desktop | 2024 | DEF CON 2024 disclosure (kb/202408c, no CVE) | Config tampering | settings.json was unprotected, so malware could silently weaken security settings. Fixed in 8.10.38 with signed settings (keys only available while unlocked); unsigned sensitive settings revert to defaults. 1P7 will not be fixed. | LOCAL-USER + FS-WRITE | https://support.1password.com/kb/202408c/ |
| 45 | 1Password 7/8 desktop | 2024 | DEF CON 2024 disclosure (kb/202408b, no CVE) | IPC (native messaging host impersonation) | No integrity check that the NMH caller is the real browser extension, so local malware can impersonate the browser. Only partially mitigated. | LOCAL-USER | https://support.1password.com/kb/202408b/ |
| 46 | 1Password 7 (Mac) | 2022 | CVE-2022-29868 | IPC process-validation bypass | A logic bug in peer-process validation let local malware exfiltrate secrets from an unlocked app. Fixed in 7.9.3. | LOCAL-USER | https://support.1password.com/kb/202204/ |
| 47 | 1Password 8 desktop | 2025 | via CVE-2025-55305 (Electron) — Trail of Bits | Code-integrity bypass (V8 heap snapshot) | Overwriting `v8_context_snapshot.bin` in a user-writable install dir backdoors the app without breaking its code signature, because ASAR integrity fuses don't cover snapshots. Fixed in 1Password 8.11.8-40. | LOCAL-USER + FS-WRITE on install dir | https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/ ; https://nvd.nist.gov/vuln/detail/CVE-2025-55305 |
| 48 | 1Password 8 desktop | 2023 | CVE-2023-4863 (libwebp, inherited) | Bundled dependency / image parsing | Chromium's libwebp heap overflow was reachable through image rendering in 1Password 8 before 8.10.15. | Crafted image displayed | https://support.1password.com/kb/202309/ |
| 49 | 1Password apps | 2022 | CVE-2022-32550 | Server authentication | Under specific circumstances a malicious server could convince a 1Password app that it was the 1Password service. | NET-MITM / MALICIOUS-SERVER | https://support.1password.com/kb/202206/ |
| 50 | 1Password CLI / SCIM (beta) | 2020 | CVE-2020-10256 | Crypto / weak RNG | An insecure PRNG generated keys in betas before Dec 2018, making encrypted data brute-forceable. | Access to encrypted data | https://support.1password.com/kb/202010/ |
| 51 | 1Password 7 (Win) | 2019 | research (ISE 2019) | Memory residue | In ISE's tests, 1Password 7 left the master password and all records in memory in both the unlocked and locked states. 1Password 4 kept an obfuscated master password after lock. | DUMP / LOCAL-USER | https://ise.io/casestudies/password-manager-hacking/ |
| 52 | Dashlane (Win) | 2019 | research (ISE 2019) | Memory residue | After an entry was edited, the whole plaintext DB stayed in memory even after lock or logout. | DUMP / LOCAL-USER | https://ise.io/casestudies/password-manager-hacking/ |
| 53 | LastPass (Win) | 2019 | research (ISE 2019) | Memory residue | The master password stayed in a string buffer after lock. LastPass fixed it. | DUMP | https://ise.io/casestudies/password-manager-hacking/ |
| 54 | Dashlane (Win) | 2017 | CVE-2017-11657 | DLL hijack | A planted WINHTTP.dll in user-writable `%APPDATA%\Dashlane` is loaded by the app. | LOCAL-USER + FS-WRITE | https://nvd.nist.gov/vuln/detail/CVE-2017-11657 ; https://www.exploit-db.com/exploits/44066 |
| 55 | LastPass (binary component) | 2017 | research (Tavis Ormandy, P0) | IPC / native component RCE | A page could reach privileged extension commands. With the native "binary component" installed, `openattach` gave remote code execution. | Malicious web page | https://threatpost.com/lastpass-fixes-ormandy-rce-bug-two-outstanding-vulnerabilities-remain/124471 |
| 56 | Enpass desktop | 2024 | CVE-2024-26362 | HTML injection in notes (desktop webview) | A crafted note renders arbitrary HTML in the Windows/Linux 6.9.2 client. The researcher reports NTLM-hash leakage via remote resources (that part unverified). | MALICIOUS-ENTRY (shared/imported vault) | https://nvd.nist.gov/vuln/detail/CVE-2024-26362 ; https://packetstormsecurity.com/files/177075/enpassda692-htmlinject.txt |
| 57 | Enpass (Win) | 2024 | CVE-2024-9203 | Memory residue | Cleartext sensitive data in memory up to 6.9.5. Fixed in 6.10.1. | DUMP / LOCAL-USER | https://nvd.nist.gov/vuln/detail/CVE-2024-9203 |
| 58 | Enpass (Win) | 2017 | vendor advisory (no CVE) | Crash-dump leakage | Windows Error Reporting saved crash dumps containing recently accessed vault data. 5.5.6 opted out of WER and told users to delete .hdmp/.mdmp files. | DUMP (WER files on disk) | https://www.enpass.io/blog/category/enpass-windows/page/2 ; https://isc.sans.edu/diary/22536 |
| 59 | Enpass (Win) | 2017 | vendor advisory (Florian Bogner, no CVE) | Local code injection | A local code injection flaw in the Windows desktop app. Fixed in 5.4 / 5.4.1. | LOCAL-USER | https://www.enpass.io/blog/enpass-windows/an-update-on-the-reported-vulnerability-of-enpass-for-windows-pc/ |
| 60 | Enpass (Win) | 2017 | vendor advisory (no CVE) | Installer | Installer vulnerability, fixed in 5.3.0 (details sparse). | Installer execution | https://www.enpass.io/?p=1281 |
| 61 | Mateso PasswordSafe (not pwsafe.org) | 2024 | CVE-2024-34538 | Crypto | "Weak cryptography" through 8.13.9.26689 (details sparse). | Access to encrypted data | https://nvd.nist.gov/vuln/detail/CVE-2024-34538 |
| 62 | Password Safe (pwsafe.org) | 2016–2026 | none found | — | No CVE found in the 10-year window. The only older CVEs are 2001–2006: clipboard/memory residue (CVE-2001-0984) and a weak rand() seed (CVE-2006-1378). | — | https://nvd.nist.gov/vuln/detail/CVE-2006-1378 |

### Context only (outside 2016–2026 but directly relevant)

- **KeePassX, CVE-2015-8378:** cancelling an XML export left a cleartext .xml file on disk.
- **KeePassX, CVE-2015-8359:** DLL preloading in the bundled Qt on Windows.
- **KeePass, CVE-2010-5196:** DwmApi.dll search-path hijack.
- **KeeFarce (2015):** DLL injection that exports an open KeePass database.
- **Gasti & Rasmussen (2012):** unauthenticated KDB/KDBX headers. Fixed by KDBX 4 header HMAC.

Sources: https://nvd.nist.gov/vuln/detail/CVE-2015-8378 ; https://keepass.info/help/kb/sec_issues.html

## 2. Grouped by vulnerability class, with a test idea for LockAlperen

### A. Memory residue: master password, keys and entries in RAM, swap, hiberfil and crash dumps
Items: 1, 7, 11, 22, 25, 26, 34, 51, 52, 53, 57, 58.
What went wrong in these products:
- UI text widgets left per-keystroke string copies (KeePass).
- Garbage-collected runtimes (CLR, V8) could not zeroize.
- Decompression buffers (zlib) kept plaintext.
- Plaintext persisted after lock.
- OS crash dumps (WER) captured process memory.

**Test idea:**
1. Type a unique canary master password, e.g. `Zq9!canaryMASTER`, into the Tauri unlock field. Give entries unique canary values.
2. Unlock, copy a password, view a TOTP, open an attachment, then lock.
3. Dump the processes:
   - Linux: `gcore` of the main process **and every WebKitGTK WebProcess/NetworkProcess**.
   - Windows: procdump `-ma` of the main exe **and each msedgewebview2.exe**.
4. Search the dumps with `strings -el` and `strings -a`. Also search for partial strings: KeePass leaked `•a`, `••b`, … fragments.
5. Repeat after lock and after a 5-minute idle.

Pass criteria:
- Zero hits in the Rust process after lock. Check that `zeroize` is used on master password buffers, the KDF output and the decompression buffers.
- Document what the webview retains: the JS heap is not zeroizable, so keep secrets out of JS as much as possible.

Also verify:
- `mlock` or `VirtualLock` on key pages.
- Core dumps disabled (`prctl(PR_SET_DUMPABLE,0)` on Linux, `WerAddExcludedApplication` or `SetErrorMode` on Windows).

### B. Clipboard
Items: 4, 13, plus the 2.8.0 Windows clipboard-format fix noted in 22's release.

**Test idea:**

Windows:
1. Enable Win+V clipboard history and cloud clipboard.
2. Copy a password from LockAlperen.
3. Confirm it does **not** appear in Win+V. That requires setting `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0` and `CanUploadToCloudClipboard=0`.

Linux:
1. Run a clipboard manager (CopyQ, KDE Klipper, GNOME extension).
2. Check that `x-kde-passwordManagerHint: secret` is set and honored.
3. Check that the clipboard is restored or cleared after the timeout under both X11 and Wayland.
4. Grep `journalctl` for the canary (repro of CVE-2022-0725).

Also confirm that clearing does not wipe unrelated data the user copied later. Compare a hash of the clipboard contents before clearing.

### C. IPC / local privilege / local service endpoints
Items: 14, 15, 19, 20, 21, 29, 42, 43, 45, 46, 55.
Typical failures:
- Weak authentication on local sockets or WebSockets.
- Peer identity not verified (getppid/XPC/NMH spoofing).
- Memory-unsafe message handling.
- Predictable shared-memory names.

**Test idea:**
1. Enumerate every local endpoint the app exposes:
   - Tauri IPC commands (`invoke` handlers).
   - Any single-instance socket or named pipe (tauri-plugin-single-instance uses D-Bus on Linux and a named mutex/pipe on Windows).
   - Deep-link handlers.
   - Localhost HTTP servers, e.g. the Google OAuth loopback redirect listener.
2. For each endpoint, connect from another same-user process and send oversized, malformed and replayed messages.
3. Specifically for the single-instance argv forwarding, check whether a second launch with crafted args can open or export a vault, or navigate the webview.
4. For the OAuth loopback listener, check:
   - The port is random.
   - `state` is checked.
   - It binds only to 127.0.0.1.
   - It shuts down after one use.
5. Audit `capabilities/*.json` so the frontend gets least-privilege permissions. No `shell:open` with arbitrary URLs, no `fs:*` scope broader than needed.

### D. File-format parsing (.lav, KDBX import, attachments)
Items: 6, 17, 18, 23, 31, 48.
Typical failures:
- XXE in the KDBX XML.
- Unbounded header or field allocations.
- Use-after-free in legacy importers.
- Unsanitised attachment file names (path traversal).
- Image decoders reachable from vault content.

**Test idea:**
1. Fuzz the `.lav` reader and the KDBX importer with `cargo fuzz` (libFuzzer) for 24h+ each. Seed with valid files and with KeePass test vectors (KDBX 3.1, KDBX 4, KDBX 4.1).
2. Add explicit regression cases:
   - A KDBX header field declaring a 4 GB length. Expect a bounded allocation and a clean error.
   - Deeply nested XML.
   - A `<!DOCTYPE … SYSTEM "file:///etc/passwd">` entity. Expect it to be rejected; confirm the XML parser (quick-xml/roxmltree) never resolves external entities.
   - A GZip bomb in the KDBX payload. Cap the decompressed size.
   - Attachment names like `../../.bashrc`, `C:\Windows\x.dll`, `CON`, and names containing NUL or RTL-override characters, saved via "save attachment". Expect them to be sanitised.
   - Inner-random-stream / protected-value edge cases.
   - Mismatched HMAC blocks. Expect a hard failure, not partial loading.

### E. Crypto / KDF / randomness
Items: 14, 27, 38, 39, 50, 61.
**Test idea:**
- Write a KDF-parameter policy test:
  - Refuse to open or save `.lav` files whose Argon2id parameters are below a floor, e.g. m ≥ 64 MiB, t ≥ 3. Mind attacker-supplied low parameters in a downgraded file.
  - Warn on KDBX imports with weak AES-KDF rounds.
- Verify nonces:
  - XChaCha nonces come from `OsRng` and are never reused across saves. Save the same vault 10k times and assert unique nonces.
  - Header and parameters are authenticated as AAD, so flipping one KDF-parameter byte must fail decryption.
- If a PIN or quick unlock is ever added, do not store a PIN-wrapped key on disk without a hardware or OS-bound secret (item 38).
- Compression-oracle check (27): if `.lav` compresses before encrypting and any field can be attacker-influenced (imports, shared vaults, favicon data), consider disabling compression or padding to buckets.

### F. Update channel / supply chain / fake installers
Items: 3, 10, 40, 41, 47.
**Test idea:**
1. MITM `latest.json` with mitmproxy.
   - Serve a higher version with an unsigned artifact, then one signed with a different key. The Tauri updater must reject both.
2. Serve a correctly signed **older** version marked as newer, or replay an old `latest.json`. Downgrade protection is needed (compare 1Password item 43).
3. Confirm the updater endpoint is HTTPS-only and the minisign pubkey is pinned in the binary.
4. Review the release pipeline (cf. Bitwarden CLI 2026):
   - Pin GitHub Actions by SHA.
   - Keep the updater private key out of the CI environment where possible, or use a protected environment with required reviewers.
   - Sign Windows binaries (Authenticode).
   - Publish SHA-256 sums.
   - Register lookalike domains or watch for malvertising.

### G. Auto-type / window targeting / synthetic input
Items: 12, 30.
**Test idea:**
1. Write a tiny helper app that sets its window title to match an entry's target (e.g. "GitHub - Sign in"), then trigger auto-type and see if credentials are typed into it.
2. Add a second helper that sends synthetic key presses (`SendInput` / `xdotool`) to trigger the global hotkey and navigate any selection popup.
   - Mitigations to verify: bind the match to the process executable path, not only the title; on Windows, detect `LLKHF_INJECTED` on the hotkey; require a physical confirmation for unmatched or ambiguous targets; keep the selection popup on top and on-screen.
3. Verify auto-type aborts if the focused window changes mid-sequence.
4. Wayland: confirm behaviour (usually unsupported), and that it fails closed.

### H. Export / config tampering / re-authentication
Items: 2, 5, 28, 44.
**Test idea:**
1. With the app closed, edit LockAlperen's config/settings file (and any Tauri store JSON) as the same user. Try to:
   - turn off auto-lock and the clipboard timeout,
   - add an auto-export path,
   - change the backup target to an attacker Google account or folder,
   - change the updater endpoint.
2. Each of these must be impossible, require unlock plus confirmation, or be signed/MACed with a vault-derived key (as 1Password did in 8.10.38).
3. Plaintext export (CSV/XML/KDBX-unencrypted) and master-password change must require re-entering the master password.
4. CSV export must neutralise `= + - @ \t \r` prefixes (CVE-2019-20184).
5. Cancelled exports must not leave temp files behind (KeePassX CVE-2015-8378).

### I. DLL / library / config search-path hijack
Items: 9, 16, 54 (and 2010/2015 context items).
**Test idea:**

Windows:
1. Run Procmon filtered on the LockAlperen process with `NAME NOT FOUND` for `.dll`, `.cnf` and `.conf`. Do this from a per-user install (`%LocalAppData%\Programs`) and when launching a `.lav` from a Downloads folder.
2. Plant a test DLL (e.g. `version.dll`, `WebView2Loader.dll`, `dwmapi.dll`) in:
   - the app dir,
   - the working directory,
   - the directory of the opened file.
3. If OpenSSL is linked (e.g. via `native-tls` or reqwest features), check for `OPENSSL_CONF` / `openssl.cnf` lookups. Prefer rustls.
4. Confirm the per-user install directory ACLs and whether the Tauri NSIS/MSI installer runs the app elevated at the end (cf. KeePassXC 2.7.11 running as SYSTEM).

Linux:
1. Check `LD_LIBRARY_PATH` / RPATH handling in the AppImage, in particular `$ORIGIN` pointing to writable dirs.

### J. Webview / remote content / HTML injection (Electron-class issues that map to Tauri)
Items: 32, 35, 36, 37, 47, 48, 56.
**Test idea:**
1. Store `<img src=x onerror=alert(1)>`, `<a href="file://attacker/share">` and `\\attacker\share\x.png` in every text field: title, username, notes, URL, custom fields, attachment names, TOTP issuer.
2. Also put them in imported KDBX fields.
3. Render each field in every view (list, detail, search results, notifications, tray menu). Expect:
   - no HTML execution,
   - no outbound SMB/HTTP requests (watch with Wireshark for NTLM leaks on Windows).
4. Tauri config checks:
   - The CSP is strict, with no `unsafe-inline` or `unsafe-eval`.
   - `dangerousRemoteDomainIpcAccess` / remote `capabilities` are not enabled.
   - Navigation to external origins is blocked (`on_navigation` handler).
5. Favicon fetching:
   - Fetch from the Rust side only.
   - Never load remote URLs directly into the webview.
   - Re-encode or validate images (size caps, PNG/ICO only, SVG banned or sanitised).
   - No redirects to `file://` or internal IPs (SSRF).
6. URL "open" actions must allow-list `http(s)` schemes only. No `file:`, `javascript:`, `ms-msdt:`, `smb:` (Bitwarden BWN-01-006).
7. Check the integrity of resources in a user-writable install dir. With Tauri, assets are embedded in the binary, which is good; still verify that nothing else, e.g. WebView2 user data or a fixed runtime, is loaded from writable paths.

### K. Local key storage / OS keychain / biometric
Items: 33, 43.
**Test idea:**
- If any key is stored in the Windows Credential Manager or the Secret Service (libsecret/KWallet) for "remember me", quick unlock or Drive OAuth tokens, read it back from a separate unprivileged process as the same user (`cmdkey` / `CredRead` / `secret-tool lookup`).
  - Document that anything readable this way is not protected against same-user malware.
  - Bind it with DPAPI plus app entropy at minimum, and prefer Windows Hello `KeyCredentialManager` / TPM-backed keys over storing the vault key.
- Check that the Google Drive refresh token is not in plaintext config.

### L. Screen capture / shoulder-surfing
No CVE found for the competitors in scope. KeePassXC and Bitwarden ship screen-capture protection as hardening.
**Test idea:**
1. On Windows, verify that `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` is applied to the main window (Tauri: `content_protected(true)`).
2. Take screenshots with Snipping Tool, OBS and Teams sharing while a password is revealed. Expect a black window.
3. On Linux, document that X11 cannot prevent capture.

### M. Re-authentication and session (lock/auto-lock)
Items: 28, plus ISE's "plaintext persists after lock" findings.
**Test idea:**
1. Automate:
   - auto-lock on idle, on screen lock (`WTSSessionChange` / logind `Lock` signal), and on suspend/hibernate,
   - plaintext/key material wiped on lock (combine with test A),
   - sensitive actions (export, KDF change, backup target change, reveal-all) re-prompting for the master password even when already unlocked.

## 3. Coverage notes and caveats

- **Disputed CVEs (2, 4, 5, 6, 25, 26, 28):** the vendor rejects them as out of the threat model (same-user or local attacker). They are still useful as test cases.
- **Recent KeePassXC 2.8.0 items (17–24):**
  - Their IDs come from the KeePassXC release notes and the MITRE CVE records fetched on 2026-11-24.
  - Some entries are still "CVE-PENDING".
  - The 6-digit CVE-2026-118673 was confirmed via the MITRE API.
- **Unverified items:**
  - KeeWeb has no CVE I could find; the item is a Packet Storm advisory only.
  - The Enpass NTLM-hash claim (item 56) is from the researcher and was not confirmed.
  - BWN-01-006 (2018) details come from secondary reporting; the 2018 PDF was not opened.
- **Not found:**
  - Keepass2Android: no format-relevant CVE.
  - Password Safe (pwsafe.org): no 2016–2026 CVE.
  - Dashlane/LastPass desktop: beyond 52–55, nothing found. Both are now primarily browser-extension products.
