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
}

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
}

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
}

export const listGroups = () => invoke<GroupView[]>("list_groups");

/** Sends the entry's secrets: only when the editor opens. */
export const entryForm = (id: string) => invoke<EntryForm>("entry_form", { id });

/** Saves to disk; nothing changes on screen if the save fails. */
export const saveEntry = (form: EntryForm) =>
  invoke<{ id: string; entries: EntrySummary[] }>("save_entry", { form });

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
}

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
