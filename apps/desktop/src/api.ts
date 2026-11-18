// Typed wrappers for the four Rust commands. These are the WebView's ONLY
// capabilities (see src-tauri/capabilities/main.json).
import { invoke } from "@tauri-apps/api/core";

export interface VaultInfo {
  name: string;
  entryCount: number;
}

/** Shown on the unlock screen. KDF values are as declared by the (not yet
 *  authenticated) header: display only. */
export interface SelectedFile {
  fileName: string;
  folder: string;
  kdf: { memoryMib: number; iterations: number; parallelism: number } | null;
  keyfileRequired: boolean;
}

// Deliberately no password, notes, TOTP or custom fields: Rust never sends them.
export interface EntrySummary {
  id: string;
  title: string;
  username: string;
  url: string;
  groupId: string;
  group: string;
  hasTotp: boolean;
  /** data: URL of a sanitized PNG, or null. */
  icon: string | null;
  /** In the recycle bin: left out of "Tüm kayıtlar" and TOTP. */
  inRecycleBin: boolean;
  /** Unix seconds; null = never expires. */
  expires: number | null;
  tags: string[];
  /** List colours, "#rrggbb" (checked by Rust). */
  fgColor: string | null;
  bgColor: string | null;
}

/** Opens the native file picker. Returns null if the user cancelled. */
export const pickVaultFile = () => invoke<SelectedFile | null>("pick_vault_file");

export const unlock = (password: string) => invoke<VaultInfo>("unlock", { password });

export const lock = () => invoke<void>("lock");

export const listEntries = () => invoke<EntrySummary[]>("list_entries");

export type CopyField = "username" | "password" | "totp";

/** Rust copies the value itself; it never comes to the WebView. Returns the
 *  seconds until the clipboard is cleared. */
export const copyField = (id: string, field: CopyField) =>
  invoke<number>("copy_field", { id, field });

/** Only on an explicit "show" click; the UI hides it again soon. */
export const revealPassword = (id: string) => invoke<string>("reveal_password", { id });

export interface LockStatus {
  unlocked: boolean;
  lockInSecs: number;
  /** One-off message from the auto-type shortcut. */
  notice: string | null;
}

/** Rust decides when to lock (idle, Windows lock, sleep); the UI only polls. */
export const lockStatus = () => invoke<LockStatus>("lock_status");

/** Save dialog for a new vault. Returns the file name, or null. */
export const pickNewVaultPath = () => invoke<string | null>("pick_new_vault_path");

/** Creates, saves and opens the new vault. Never overwrites a file. */
export const createVault = (name: string, password: string, confirm: string) =>
  invoke<{ file: SelectedFile; info: VaultInfo }>("create_vault", { name, password, confirm });

export interface RecentVault {
  fileName: string;
  folder: string;
  /** Unix seconds. */
  opened: number;
}

export const recentVaults = () => invoke<RecentVault[]>("recent_vaults");

/** Chooses by position; Rust holds the paths. */
export const selectRecent = (index: number) => invoke<SelectedFile>("select_recent", { index });

export const forgetRecent = (index: number) => invoke<RecentVault[]>("forget_recent", { index });

export interface GroupView {
  id: string;
  name: string;
  parent: string | null;
  entries: number;
  totalEntries: number;
  /** Font Awesome key chosen in the app, or null. */
  icon: string | null;
  /** This folder is the recycle bin. */
  recycleBin: boolean;
}

/** True if the folder is the recycle bin or inside it. */
export function inRecycleBin(groupId: string, groups: GroupView[]): boolean {
  const seen = new Set<string>();
  let cur = groups.find((g) => g.id === groupId);
  while (cur && !seen.has(cur.id)) {
    if (cur.recycleBin) return true;
    seen.add(cur.id);
    cur = groups.find((g) => g.id === cur!.parent);
  }
  return false;
}

/** Deletes everything in the recycle bin for good. */
export const emptyRecycleBin = () => invoke<EntrySummary[]>("empty_recycle_bin");

/** Holds secrets while the editor is open. */
export interface EntryForm {
  id: string | null;
  groupId: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  tags: string[];
  /** Base32 secret or otpauth:// URI; "" = none. */
  totp: string;
  /** Custom fields; null/absent = keep unchanged. */
  fields?: FormField[] | null;
  /** Expiry as Unix seconds (KeePass "Expires"); null = never. */
  expires?: number | null;
  /** Auto-type sequence; "" = {USERNAME}{TAB}{PASSWORD}{ENTER}. */
  autotypeSequence?: string;
  /** Window rule with * and ?; "" = the entry's title or site. */
  autotypeWindow?: string;
  /** false = this entry never auto-types. */
  autotypeEnabled?: boolean;
  /** List colours, "#rrggbb"; null = none. */
  fgColor?: string | null;
  bgColor?: string | null;
}

/** KeePass field reference to another entry's field (resolved by Rust when
 *  copying or auto-typing). what: T title, U username, P password, A site,
 *  N notes. */
export function fieldReference(id: string, what: "T" | "U" | "P" | "A" | "N"): string {
  return `{REF:${what}@I:${id.replace(/-/g, "").toUpperCase()}}`;
}

/** The placeholders an auto-type sequence may use. */
export const SEQUENCE_TOKENS = [
  "{USERNAME}",
  "{PASSWORD}",
  "{TAB}",
  "{ENTER}",
  "{TOTP}",
  "{TITLE}",
  "{URL}",
  "{NOTES}",
  "{SPACE}",
  "{DELAY 500}",
  "{S:Alan adı}",
];

export interface FormField {
  name: string;
  value: string;
  protected: boolean;
}

export interface GenOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
  /** Non-empty = generate from this pattern instead (see PATTERN_HELP). */
  pattern?: string;
}

/** A saved generator profile (KeePass "Password Generator" profiles). */
export interface GenProfile extends GenOptions {
  name: string;
  pattern: string;
}

/** Placeholders of a generator pattern. */
export const PATTERN_HELP: [string, string][] = [
  ["d", "rakam"],
  ["l", "küçük harf"],
  ["u", "büyük harf"],
  ["L", "harf"],
  ["a", "küçük harf ya da rakam"],
  ["U", "büyük harf ya da rakam"],
  ["A", "harf ya da rakam"],
  ["s", "sembol"],
  ["h / H", "onaltılık rakam (küçük / büyük)"],
  ["\\x", "x karakterinin kendisi"],
  ["{n}", "öncekini n kez tekrarla"],
];

const PATTERN_SETS: Record<string, number> = {
  d: 10,
  l: 26,
  u: 26,
  L: 52,
  a: 36,
  U: 36,
  A: 62,
  s: 27,
  h: 16,
  H: 16,
};

/** Upper bound of a pattern's entropy in bits; null if it is not valid
 *  (Rust checks it again). */
export function patternBits(p: string): number | null {
  const items: number[] = [];
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "\\") {
      if (i + 1 >= p.length) return null;
      items.push(0);
      i++;
    } else if (c === "{") {
      const end = p.indexOf("}", i);
      const n = end > i ? Number(p.slice(i + 1, end)) : NaN;
      if (!Number.isInteger(n) || n < 1 || n > 256 || items.length === 0) return null;
      const last = items[items.length - 1];
      for (let k = 1; k < n; k++) items.push(last);
      i = end;
    } else {
      items.push(PATTERN_SETS[c] ? Math.log2(PATTERN_SETS[c]) : 0);
    }
    if (items.length > 256) return null;
  }
  return items.length ? items.reduce((a, b) => a + b, 0) : null;
}

/** KeePass's built-in profiles (patterns), shown before the user's own. */
export const BUILTIN_PROFILES: GenProfile[] = [
  ["40 bit onaltılık anahtar", "h{10}"],
  ["128 bit onaltılık anahtar", "h{32}"],
  ["256 bit onaltılık anahtar", "h{64}"],
  ["MAC adresi", "HH\\-HH\\-HH\\-HH\\-HH\\-HH"],
  ["6 haneli PIN", "d{6}"],
].map(([name, pattern]) => ({
  name,
  pattern,
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
}));

export const getGenProfiles = () => invoke<GenProfile[]>("get_gen_profiles");
export const setGenProfiles = (list: GenProfile[]) =>
  invoke<GenProfile[]>("set_gen_profiles", { list });

/** Ids of entries whose notes or custom fields contain the text (Rust
 *  searches; protected field values are never searched). */
export const searchHidden = (query: string, scope: { notes: boolean; fields: boolean }) =>
  invoke<string[]>("search_hidden", { query, scope });

export interface VaultSettings {
  name: string;
  description: string;
  historyLimit: number;
  historyVersions: number;
  kdf: { memoryMib: number; iterations: number; parallelism: number };
  keyfileRequired: boolean;
  keyfileName: string | null;
}

export const vaultSettings = () => invoke<VaultSettings>("vault_settings");
export const setVaultSettings = (name: string, description: string, historyLimit: number) =>
  invoke<EntrySummary[]>("set_vault_settings", { name, description, historyLimit });
export const clearHistory = (olderThanDays: number | null) =>
  invoke<number>("clear_history", { olderThanDays });
export const changeKdf = (
  current: string,
  memoryMib: number,
  iterations: number,
  parallelism: number,
) => invoke<void>("change_kdf", { current, memoryMib, iterations, parallelism });
/** create: a new random key file (save dialog); otherwise pick one. */
export const pickNewKeyfile = (create: boolean) =>
  invoke<string | null>("pick_new_keyfile", { create });
export const changeKeyfile = (current: string, usePending: boolean) =>
  invoke<void>("change_keyfile", { current, usePending });

export const pickMergeFile = () => invoke<string | null>("pick_merge_file");
export const pickMergeKeyfile = () => invoke<string | null>("pick_merge_keyfile");
export interface MergeSummary {
  added: number;
  updated: number;
  removed: number;
  groupsAdded: number;
}
export const mergeVault = (password: string) =>
  invoke<{ summary: MergeSummary; entries: EntrySummary[] }>("merge_vault", { password });

export const exportKdbx = (current: string, kdbxPassword: string) =>
  invoke<boolean>("export_kdbx", { current, kdbxPassword });
export const exportHtml = (current: string, includePasswords: boolean, generated: string) =>
  invoke<boolean>("export_html", { current, includePasswords, generated });

/** Argon2id presets for "Kasa ayarları" (memory MiB, passes, lanes). */
export const KDF_PRESETS: { label: string; memoryMib: number; iterations: number; parallelism: number }[] = [
  { label: "Standart (64 MiB, 3 geçiş)", memoryMib: 64, iterations: 3, parallelism: 4 },
  { label: "Güçlü (256 MiB, 4 geçiş)", memoryMib: 256, iterations: 4, parallelism: 4 },
  { label: "Çok güçlü (1 GiB, 4 geçiş)", memoryMib: 1024, iterations: 4, parallelism: 4 },
];

/** Google Drive backup (src-tauri/src/gdrive.rs). Only the encrypted vault
 *  file goes to Drive; the app can see only the files it created. */
export interface DriveStatus {
  configured: boolean;
  connected: boolean;
  auto: boolean;
  clientId: string;
  lastBackup: number | null;
  lastError: string | null;
}
export interface DriveFile {
  id: string;
  name: string;
  modifiedTime: string;
  size: string | null;
}
export const gdriveStatus = () => invoke<DriveStatus>("gdrive_status");
export const gdriveSetClient = (clientId: string, clientSecret: string) =>
  invoke<DriveStatus>("gdrive_set_client", { clientId, clientSecret });
export const gdriveConnect = () => invoke<DriveStatus>("gdrive_connect");
export const gdriveDisconnect = () => invoke<DriveStatus>("gdrive_disconnect");
export const gdriveSetAuto = (on: boolean) => invoke<DriveStatus>("gdrive_set_auto", { on });
export const gdriveBackupNow = () => invoke<DriveStatus>("gdrive_backup_now");
export const gdriveList = () => invoke<DriveFile[]>("gdrive_list");
export const gdriveRestore = (id: string, name: string) =>
  invoke<string | null>("gdrive_restore", { id, name });

/** One open vault tab (no secrets: vault or file name). */
export interface TabView {
  index: number;
  title: string;
  unlocked: boolean;
  active: boolean;
}
export const listTabs = () => invoke<TabView[]>("list_tabs");
export const newTab = () => invoke<TabView[]>("new_tab");
export const switchTab = (index: number) => invoke<TabView[]>("switch_tab", { index });
export const closeTab = (index: number) => invoke<TabView[]>("close_tab", { index });
/** The active tab: its chosen file and, if unlocked, the vault. */
export const tabState = () =>
  invoke<{ file: SelectedFile | null; info: VaultInfo | null }>("tab_state");

export const listGroups = () => invoke<GroupView[]>("list_groups");

/** Sets a folder's icon (a key from folderIcons.tsx; null = default). Rust
 *  accepts only short lowercase names. */
export const setGroupIcon = (id: string, icon: string | null) =>
  invoke<EntrySummary[]>("set_group_icon", { id, icon });

/** Moves a folder (with its subfolders and entries); null = top level.
 *  Rust refuses moving the root or into itself / its subfolders. */
export const moveGroup = (id: string, parent: string | null) =>
  invoke<EntrySummary[]>("move_group", { id, parent });

/** Moves an entry to another folder (not an edit: no history version). */
export const moveEntry = (id: string, group: string) =>
  invoke<EntrySummary[]>("move_entry", { id, group });

/** Sends the entry's secrets: only when the editor opens. */
export const entryForm = (id: string) => invoke<EntryForm>("entry_form", { id });

/** Saves to disk; nothing changes on screen if the save fails. */
export const saveEntry = (form: EntryForm) =>
  invoke<{ id: string; entries: EntrySummary[] }>("save_entry", { form });

/** KeePass "Duplicate Entry": a copy in the same folder, without history. */
export const duplicateEntry = (id: string) =>
  invoke<{ id: string; entries: EntrySummary[] }>("duplicate_entry", { id });

export const deleteEntry = (id: string) => invoke<EntrySummary[]>("delete_entry", { id });

export const generatePassword = (options: GenOptions) =>
  invoke<string>("generate_password", { options });

export interface TotpCode {
  code: string;
  secondsLeft: number;
  period: number;
}

/** Current code only; the TOTP secret never leaves Rust here. */
export const totpCode = (id: string) => invoke<TotpCode>("totp_code", { id });

export type Issue = "weak" | "reused" | "expired";

export interface HealthReport {
  checked: number;
  weak: number;
  reused: number;
  expired: number;
  okPercent: number;
  entries: { id: string; issues: Issue[] }[];
}

/** Counts and labels only; passwords never leave Rust. */
export const passwordHealth = () => invoke<HealthReport>("password_health");

export interface ImportSummary {
  groups: number;
  entries: number;
  totp: number;
  attachments: number;
  customFields: number;
  skippedRecycleBin: number;
  skippedHistory: number;
  folder: string;
}

/** KeePass file picker (Rust holds the path). Returns the file name or null. */
export const pickKdbxFile = () => invoke<string | null>("pick_kdbx_file");

export const importKdbx = (password: string) =>
  invoke<{ summary: ImportSummary; entries: EntrySummary[] }>("import_kdbx", { password });

/** Key file picker (Rust holds the path). Returns the file name or null. */
export const pickKeyfile = () => invoke<string | null>("pick_keyfile");

export const clearKeyfile = () => invoke<void>("clear_keyfile");

export interface EntryExtras {
  fields: { name: string; value: string | null; protected: boolean }[];
  attachments: { name: string; size: number }[];
  history: { modified: number; title: string; username: string; passwordDiffers: boolean }[];
  tags: string[];
  hasNotes: boolean;
  created: number;
  modified: number;
  /** Unix seconds; null = never expires. */
  expires: number | null;
}

export type Extra = { kind: "notes" } | { kind: "custom"; index: number };

/** Metadata only: protected values and notes are not included. */
export const entryExtras = (id: string) => invoke<EntryExtras>("entry_extras", { id });

export const revealExtra = (id: string, what: Extra) => invoke<string>("reveal_extra", { id, what });

export const copyExtra = (id: string, what: Extra) => invoke<number>("copy_extra", { id, what });

/** Save dialog in Rust; returns false if cancelled. The file is NOT encrypted. */
export const saveAttachment = (id: string, index: number) =>
  invoke<boolean>("save_attachment", { id, index });

export interface Settings {
  idleMinutes: number;
  /** Look for a new version at startup (Rust decides where and verifies). */
  checkUpdates: boolean;
  /** The close button hides the window to the system tray. */
  closeToTray: boolean;
  /** Global shortcut that types into the window in front (one matching entry). */
  autotypeShortcut: Shortcut;
  /** "system" follows Windows. */
  theme: Theme;
  listStyle: ListStyle;
  /** Seconds before a copied value is cleared (CLIPBOARD_CHOICES). */
  clipboardSeconds: number;
  /** Lock on Win+L, sleep, disconnect and logoff. */
  lockOnSystemEvents: boolean;
  // ----- From KeePass "Options" -----
  lockOnMinimize: boolean;
  exitInsteadOfLock: boolean;
  minimizeAfterCopy: boolean;
  minimizeOnLock: boolean;
  alwaysOnTop: boolean;
  minimizeToTray: boolean;
  startMinimized: boolean;
  showWindowShortcut: ShowShortcut;
  /** Mirrors the HKCU Run key (Rust reads and writes it). */
  runAtStartup: boolean;
  showExpiredOnOpen: boolean;
  autoGeneratePassword: boolean;
  generator: GenOptions;
}

export type ShowShortcut = "off" | "ctrl-alt-k" | "ctrl-alt-shift-w";

export const SHOW_SHORTCUTS: { value: ShowShortcut; label: string }[] = [
  { value: "ctrl-alt-k", label: "Ctrl+Alt+K (KeePass ile aynı)" },
  { value: "ctrl-alt-shift-w", label: "Ctrl+Alt+Shift+W" },
  { value: "off", label: "Kapalı" },
];

/** Generator length limits (Rust clamps to the same). */
export const GEN_MIN_LENGTH = 8;
export const GEN_MAX_LENGTH = 128;

export const CLIPBOARD_CHOICES = [5, 10, 12, 15, 20, 30, 45, 60, 90];

export type ListStyle = "list" | "compact" | "grid" | "table";

export type Theme = "system" | "light" | "dark";

const darkQuery = window.matchMedia("(prefers-color-scheme: dark)");
let currentTheme: Theme = "system";

/** Paints the native title bar like the page (Windows 11; ignored on 10). */
function syncTitlebar() {
  const dark = currentTheme === "dark" || (currentTheme === "system" && darkQuery.matches);
  invoke("set_titlebar", { dark }).catch(() => {});
}

// "Windows ile aynı": follow Windows when its theme changes.
darkQuery.addEventListener("change", () => {
  if (currentTheme === "system") syncTitlebar();
});

/** Applies the colour theme (styles.css): "system" leaves it to Windows. */
export function applyTheme(theme: Theme) {
  currentTheme = theme;
  const root = document.documentElement;
  if (theme === "system") delete root.dataset.theme;
  else root.dataset.theme = theme;
  syncTitlebar();
}

export type Shortcut = "off" | "ctrl-alt-a" | "ctrl-alt-shift-a" | "ctrl-alt-shift-k" | "ctrl-alt-shift-l";

export const SHORTCUTS: { value: Shortcut; label: string }[] = [
  { value: "ctrl-alt-a", label: "Ctrl+Alt+A (KeePass ile aynı)" },
  { value: "ctrl-alt-shift-a", label: "Ctrl+Alt+Shift+A" },
  { value: "ctrl-alt-shift-k", label: "Ctrl+Alt+Shift+K" },
  { value: "ctrl-alt-shift-l", label: "Ctrl+Alt+Shift+L" },
  { value: "off", label: "Kapalı" },
];

/** False if the shortcut is off, or another program already owns it. */
/** Whether each global shortcut is registered (false: off, or taken by
 *  another program). */
export const hotkeyActive = () =>
  invoke<{ autotype: boolean; showWindow: boolean }>("hotkey_active");

export const IDLE_CHOICES = [1, 2, 5, 10, 15, 30, 60];

export const getSettings = () => invoke<Settings>("get_settings");

export const setSettings = (value: Settings) => invoke<Settings>("set_settings", { value });

export const appVersion = () => invoke<string>("app_version");

export interface AvailableUpdate {
  version: string;
  notes: string | null;
}

/** null = up to date. Throws a Turkish message on network/config errors. */
export const checkUpdate = () => invoke<AvailableUpdate | null>("check_update");

/** Locks the vault, installs the update found by checkUpdate and restarts.
 *  Resolves only if something failed (it throws then). */
export const installUpdate = () => invoke<void>("install_update");

export const addGroup = (parent: string | null, name: string) =>
  invoke<string>("add_group", { parent, name });
export const renameGroup = (id: string, name: string) =>
  invoke<EntrySummary[]>("rename_group", { id, name });
/** Deletes the folder, its subfolders AND their entries. */
export const deleteGroup = (id: string) => invoke<EntrySummary[]>("delete_group", { id });
export const restoreVersion = (id: string, index: number) =>
  invoke<EntrySummary[]>("restore_version", { id, index });
/** File picker in Rust; returns false if cancelled. */
export const addAttachment = (id: string) => invoke<boolean>("add_attachment", { id });
export const removeAttachment = (id: string, index: number) =>
  invoke<void>("remove_attachment", { id, index });
export const changeMaster = (current: string, newPassword: string, confirm: string) =>
  invoke<void>("change_master", { current, new: newPassword, confirm });
/** Re-checks the master password; writes a PLAIN-TEXT CSV. */
export const exportCsv = (current: string) => invoke<boolean>("export_csv", { current });
export const pickImportKeyfile = () => invoke<string | null>("pick_import_keyfile");
/** Downloads missing site icons (automatic; each entry tried once per run). */
export const fetchIcons = () =>
  invoke<{ fetched: number; failed: number; remaining: number; entries: EntrySummary[] }>(
    "fetch_icons",
  );
/** Minimizes the app; types into the verified window the user switches to. */
export const autoType = (id: string) => invoke<void>("auto_type", { id });

/** Rust opens the entry's own address, and only if it is http(s). */
export const openUrl = (id: string) => invoke<void>("open_url", { id });

/** Rust returns user-facing strings; anything else is shown generically. */
export function errorText(e: unknown): string {
  return typeof e === "string" ? e : "Beklenmeyen bir hata oluştu.";
}

// ----- Expiry dates (local calendar day <-> Unix seconds) -----

/** Local midnight of the day `months` from today, in Unix seconds. */
export function expiryAfterMonths(months: number): number {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  d.setMonth(d.getMonth() + months);
  return Math.floor(d.getTime() / 1000);
}

/** `YYYY-MM-DD` (local) for an <input type="date">. */
export function dateInputValue(unix: number): string {
  const d = new Date(unix * 1000);
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getFullYear(), 4)}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** Local midnight of a `YYYY-MM-DD` value; null if empty or invalid. */
export function fromDateInput(value: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!m) return null;
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  const t = Math.floor(d.getTime() / 1000);
  return Number.isFinite(t) && t >= 0 ? t : null;
}